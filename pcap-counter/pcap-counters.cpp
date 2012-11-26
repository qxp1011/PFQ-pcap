/***************************************************************
 *                                                
 * (C) 2011 - Nicola Bonelli <nicola.bonelli@cnit.it>   
 *            Andrea Di Pietro <andrea.dipietro@for.unipi.it>
 *
 ****************************************************************/

#include <affinity.hpp>

#include <iostream>
#include <fstream>
#include <sstream>

#include <thread>
#include <string>
#include <cstring>
#include <vector>
#include <algorithm>
#include <iterator>
#include <atomic>
#include <cmath>
#include <tuple>
#include <unordered_set>

#include <netinet/ip.h>
#include <netinet/udp.h>

#include <pcap/pcap.h>

namespace opt {

    int sleep_microseconds;

    size_t caplen = 64;

    bool flow = false;

    const char *filter;

    static const int seconds = 600;
}


typedef std::tuple<std::string, int, std::vector<int>> binding_type;


typedef std::tuple<uint32_t, uint32_t, uint16_t, uint16_t> Tuple;


struct HashTuple {

    uint32_t operator()(Tuple const &t) const
    {

        return std::get<0>(t) ^ std::get<1>(t) ^
               std::get<2>(t) ^ (std::get<3>(t) << 16);
    }

};


namespace vt100
{
    const char * const CLEAR = "\E[2J";
    const char * const EDOWN = "\E[J";
    const char * const DOWN  = "\E[1B";
    const char * const HOME  = "\E[H";
    const char * const ELINE = "\E[K";
    const char * const BOLD  = "\E[1m";
    const char * const RESET = "\E[0m";
    const char * const BLUE  = "\E[1;34m";
    const char * const RED   = "\E[31m";
}


binding_type 
binding_parser(const char *arg)
{
    int core, q; char sep;
    std::vector<int> queues;

    auto sc = std::find(arg, arg+strlen(arg), ':');
    if (sc == arg + strlen(arg)) {
        std::string err("'");
        err.append(arg)
           .append("' option error: ':' not found");
        throw std::runtime_error(err);
    }

    std::string dev(arg, sc);

    std::istringstream i(std::string(sc+1, arg+strlen(arg)));  

    if(!(i >> core))
        throw std::runtime_error("arg: parse error");

    while((i >> sep >> q))
        queues.push_back(q);
    
    return std::make_tuple(dev, core, queues);
}

namespace test
{
    struct ctx
    {
        char m_error[PCAP_ERRBUF_SIZE];

        ctx(int id, const char *d, const std::vector<int> & q)
        : m_id(id), m_dev(d), m_queues(q), m_stop(false), m_pcap(pcap_open_live(d, opt::caplen, 1, -1, m_error)), m_read()
        {
            if (m_pcap == nullptr)
            {
                throw std::runtime_error(std::string("pcap_open_live: ") + m_error);
            }

            if (opt::filter)
            {
                struct bpf_program fp;
                if (pcap_compile(m_pcap, &fp, opt::filter, 1, PCAP_NETMASK_UNKNOWN) < 0)
                    throw std::runtime_error(std::string("pcap_compile"));

                if (pcap_setfilter(m_pcap, &fp) < 0)
                    throw std::runtime_error("pcap_setfilter");

                pcap_freecode(&fp); 
            }
        }
        
        ctx(const ctx &) = delete;
        ctx& operator=(const ctx &) = delete;

        ctx(ctx && other)
        : m_id(other.m_id), m_dev(other.m_dev), m_queues(other.m_queues), m_stop(other.m_stop.load()), 
          m_pcap(other.m_pcap), m_read()
        {
            other.m_pcap = nullptr;
        }


        ~ctx()
        {
            if (m_pcap)
            {
                pcap_close(m_pcap);
            }
        }

        ctx& operator=(ctx &&other)
        {
            m_id = other.m_id;
            m_dev = other.m_dev;
            m_queues = other.m_queues;
            m_stop.store(other.m_stop.load());
            m_pcap = std::move(other.m_pcap);

            other.m_pcap = nullptr;
            return *this;
        }

        
        static void handler(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
        {                       
            ctx * that = reinterpret_cast<ctx *>(user);

            if (that->m_stop.load(std::memory_order_relaxed))
                pcap_breakloop(that->m_pcap);

            that->m_read++;
        }
       

        void operator()() 
        {
            for(;;)
            {
                auto n = pcap_dispatch(m_pcap, -1, handler, (u_char *)this);
                if (n == -2)
                    return;
                if (n == -1)
                    throw std::runtime_error("pcap_dispatch");
            }
        }


        void stop()
        {
            m_stop.store(true, std::memory_order_release);
        }

        pcap_stat
        stats() const
        {
            struct pcap_stat t;
            
            if (pcap_stats(m_pcap, &t) < 0)
                throw std::runtime_error("pcap_stats");
            return t;
        }

        unsigned long long 
        read() const
        {
            return m_read;
        }

        unsigned long 
        flow() const
        {
            return m_flow;
        }

        size_t 
        batch() const
        {
            return m_batch;
        }

    private:
        int m_id;

        const char *m_dev;
        std::vector<int> m_queues;

        std::atomic_bool m_stop;
        
        pcap_t *m_pcap;        

        unsigned long long m_read;
        size_t m_batch;

        std::unordered_set<std::tuple<uint32_t, uint32_t, uint16_t, uint16_t>, HashTuple> m_set;

        unsigned long m_flow;

    } __attribute__((aligned(128)));
}


unsigned int hardware_concurrency()
{
    auto proc = []() {
        std::ifstream cpuinfo("/proc/cpuinfo");
        return std::count(std::istream_iterator<std::string>(cpuinfo),
                          std::istream_iterator<std::string>(),
                          std::string("processor"));
    };
   
    return std::thread::hardware_concurrency() ? : proc();
}


void usage(const char *name)
{
    throw std::runtime_error(std::string("usage: ")
               .append(name)
               .append("[-h|--help] [-c caplen] [-f | --flow] [-bpf | --filter filter] T1 T2... \n\t| T = dev:core:queue,queue..."));
}


int
main(int argc, char *argv[])
try
{
    if (argc < 2)
        usage(argv[0]);

    std::vector<std::thread> vt;
    std::vector<test::ctx> ctx;

    std::vector<binding_type> vbinding;

    // load vbinding vector:
    for(int i = 1; i < argc; ++i)
    {
        if ( strcmp(argv[i], "-c") == 0 ||
             strcmp(argv[i], "--caplen") == 0) {
            i++;
            if (i == argc)
            {
                throw std::runtime_error("caplen missing");
            }

            opt::caplen = std::atoi(argv[i]);
            continue;
        }

        if ( strcmp(argv[i], "-f") == 0 ||
             strcmp(argv[i], "--flow") == 0)
        {
            opt::flow = true;
            continue;
        }

        if ( strcmp(argv[i], "-bpf") == 0 ||
             strcmp(argv[i], "--filter") == 0) {
            i++;
            if (i == argc)
            {
                throw std::runtime_error("filter missing");
            }

            opt::filter = argv[i];
            continue;
        }

        if ( strcmp(argv[i], "-h") == 0 ||
             strcmp(argv[i], "--help") == 0)
            usage(argv[0]);

        vbinding.push_back(binding_parser(argv[i]));
    }
    
    std::cout << "caplen: " << opt::caplen << std::endl;

    // create threads' context:
    //
    for(unsigned int i = 0; i < vbinding.size(); ++i)
    {
        std::cout << "pushing a context: " << std::get<0>(vbinding[i]) << ' ' << std::get<1>(vbinding[i]) << std::endl;
        ctx.push_back(test::ctx(i, std::get<0>(vbinding[i]).c_str(), std::get<2>(vbinding[i])));        
    }

    opt::sleep_microseconds = 50000 * ctx.size();
    std::cout << "poll timeout " << opt::sleep_microseconds << " usec" << std::endl;

    // create threads:

    int i = 0;
    std::for_each(vbinding.begin(), vbinding.end(), [&](const binding_type &b) {
                  std::thread t(std::ref(ctx[i++]));
                  std::cout << "thread on core " << std::get<1>(b) << " -> queues [";

                  std::copy(std::get<2>(b).begin(), std::get<2>(b).end(),
                            std::ostream_iterator<int>(std::cout, " "));
                  std::cout << "]\n";

                  extra::set_affinity(t, std::get<1>(b));
                  vt.push_back(std::move(t));
                  });

    unsigned long long sum, flow, old = 0;
    struct pcap_stat sum_stats, old_stats = {0,0,0};

    std::cout << "----------- capture started ------------\n";

    auto begin = std::chrono::system_clock::now();

    for(int y=0; y < opt::seconds; y++)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        sum = 0;
        flow = 0;
        sum_stats = {0,0,0};

        std::for_each(ctx.begin(), ctx.end(), [&](const test::ctx &c) {
                        sum += c.read();
                        flow += c.flow();
                        
                        sum_stats.ps_recv   += c.stats().ps_recv   ;
                        sum_stats.ps_drop   += c.stats().ps_drop   ;
                        sum_stats.ps_ifdrop += c.stats().ps_ifdrop ;
                      });
    
        std::cout << "recv: ";
        std::for_each(ctx.begin(), ctx.end(), [&](const test::ctx &c) {
            std::cout << c.stats().ps_recv << ' ';
        });
        std::cout << " -> " << sum_stats.ps_recv << std::endl;

        std::cout << "drop: ";
        std::for_each(ctx.begin(), ctx.end(), [&](const test::ctx &c) {
            std::cout << c.stats().ps_drop << ' ';
        });
        std::cout << " -> " << sum_stats.ps_drop << std::endl;

        std::cout << "ifdrop: ";
        std::for_each(ctx.begin(), ctx.end(), [&](const test::ctx &c) {
            std::cout << c.stats().ps_ifdrop << ' ';
        });
        std::cout << " -> " << sum_stats.ps_ifdrop << std::endl;
        
        std::cout << "max_batch: ";
        std::for_each(ctx.begin(), ctx.end(), [&](const test::ctx &c) {
            std::cout << c.batch() << ' ';
        });
        std::cout << std::endl;

        auto end = std::chrono::system_clock::now();

        std::cout << "capture: " << vt100::BOLD << 
                ((sum-old)*1000000)/std::chrono::microseconds(end-begin).count() 
                    << vt100::RESET << " pkt/sec"; 
        
        if (flow) {
            std::cout << " flow: " << flow;    
        }

        std::cout << std::endl; 

        old = sum, begin = end;
        old_stats = sum_stats;
    }

    std::for_each(ctx.begin(), ctx.end(), std::mem_fn(&test::ctx::stop));
    std::for_each(vt.begin(), vt.end(), std::mem_fn(&std::thread::join));

    return 0;
}
catch(std::exception &e)
{
    std::cerr << e.what() << std::endl;
}
