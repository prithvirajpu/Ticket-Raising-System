import React, { useEffect, useState, useRef, useCallback } from 'react';
import { 
  Ticket, 
  Info, 
  History, 
  CheckCircle, 
  Plus,
  ShieldCheck,
  Clock,
  Users,
  BarChart3,
} from 'lucide-react';
import DashboardLayout from '../../layouts/DashboardLayout';
import { useNavigate } from 'react-router-dom';
import StatsCard from '../../components/StatsCard';
import Footer from '../../components/Footer';
import { getUserDashboard } from '../../services/ticketService';
import BlackHole from '../../components/BlackHole';

const UserDashboard = () => {
  const [data, setData] = useState({});
  const [animate, setAnimate] = useState(false);
  const [visibleSections, setVisibleSections] = useState({});
  const [isTouchDevice, setIsTouchDevice] = useState(false);
  const containerRef = useRef(null);
  const navigate = useNavigate();

  // 3D Parallax mouse tracking state
  const [tilt, setTilt] = useState({ x: 0, y: 0 });

  const rectRef = useRef(null);
  const rafRef = useRef(null);

  useEffect(() => {
    fetchData();
    
    // Check if the device uses touch mechanics
    const touchCheck = window.matchMedia("(pointer: coarse)").matches;
    setIsTouchDevice(touchCheck);

    // Trigger snappier entrance animation for main frame
    const animFrame = requestAnimationFrame(() => {
      const timer = setTimeout(() => setAnimate(true), 50); // Faster trigger
      return () => clearTimeout(timer);
    });

    // Intersection Observer for rapid staggered scroll entry
    const observerOptions = {
      root: null,
      threshold: 0.05, // Triggers slightly earlier for responsiveness
      rootMargin: "0px 0px -30px 0px"
    };

    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          const sectionId = entry.target.getAttribute('data-section');
          setVisibleSections((prev) => ({ ...prev, [sectionId]: true }));
        }
      });
    }, observerOptions);

    const targets = document.querySelectorAll('[data-section]');
    targets.forEach((target) => observer.observe(target));

    return () => {
      cancelAnimationFrame(animFrame);
      observer.disconnect();
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, []);

  const fetchData = async () => {
    try {
      const res = await getUserDashboard();
      setData(res.message);
    } catch (error) {
      console.log(error);
    }
  };

  const measureRect = useCallback(() => {
    if (containerRef.current) {
      rectRef.current = containerRef.current.getBoundingClientRect();
    }
  }, []);

  useEffect(() => {
    measureRect();
    window.addEventListener('resize', measureRect);
    return () => window.removeEventListener('resize', measureRect);
  }, [measureRect]);

  const handleMouseEnter = () => {
    if (isTouchDevice) return;
    measureRect();
  };

  const handleMouseMove = (e) => {
    if (isTouchDevice || e.nativeEvent.sourceCapabilities?.firesTouchEvents) return;
    
    const rect = rectRef.current;
    if (!rect) return;

    if (rafRef.current) cancelAnimationFrame(rafRef.current);

    const clientX = e.clientX;
    const clientY = e.clientY;

    rafRef.current = requestAnimationFrame(() => {
      const width = rect.width;
      const height = rect.height;
      const mouseX = clientX - rect.left - width / 2;
      const mouseY = clientY - rect.top - height / 2;

      const rX = -(mouseY / height) * 4; 
      const rY = (mouseX / width) * 4;

      setTilt({ x: rX, y: rY });
    });
  };

  const handleMouseLeave = () => {
    if (isTouchDevice) return;
    if (rafRef.current) cancelAnimationFrame(rafRef.current);
    setTilt({ x: 0, y: 0 });
  };

  return (
    <DashboardLayout title="Dashboard" subtitle="Manage your assigned tickets">
      {/* Top Header Button */}
      {/* Top Header Button */}
<div className="flex justify-end mb-6 -mt-12 sm:-mt-16">
  <button
    onClick={() => navigate('/user/create-ticket')}
    className="group relative flex items-center justify-center gap-2 bg-neutral-950 text-white p-2.5 sm:px-5 sm:py-2.5 rounded-xl sm:rounded-xl hover:bg-black transition-all text-sm font-bold shadow-md hover:shadow-neutral-200/15 active:scale-95 duration-200"
    title="Raise New Ticket"
  >
    <Plus size={18} className="transition-transform group-hover:rotate-90 duration-200 ease-out flex-shrink-0" />
    <span className="hidden sm:inline">Raise New Ticket</span>
  </button>
</div>

      {/* Outer clip wrapper */}
      <div className="overflow-hidden w-full select-none md:select-text" style={{ touchAction: 'pan-y' }}>
        {/* Main Showcase Frame (Reduced from duration-700 to duration-300) */}
        <div 
          ref={containerRef}
          onMouseEnter={handleMouseEnter}
          onMouseMove={handleMouseMove}
          onMouseLeave={handleMouseLeave}
          className={`transition-all duration-300 ease-out ${isTouchDevice ? '' : 'transform-gpu will-change-transform'}`}
          style={{
            transform: !animate 
              ? (isTouchDevice ? 'none' : 'perspective(1500px) rotateX(4deg) scale(0.98)')
              : (isTouchDevice ? 'none' : `perspective(1500px) rotateX(${tilt.x}deg) rotateY(${tilt.y}deg) scale(1)`),
            opacity: animate ? 1 : 0,
            transformOrigin: 'center center'
          }}
        >
          {/* Modern Bento Container */}
          <div className="relative rounded-3xl border border-neutral-200/60 bg-neutral-50/40 p-6 md:p-8 overflow-hidden shadow-sm">

            {/* Ambient Spotlights */}
            <div className="absolute top-0 left-1/4 w-96 h-96 bg-gradient-to-tr from-sky-200/20 via-indigo-100/30 to-violet-200/20 blur-3xl rounded-full pointer-events-none animate-[pulse_8s_infinite_alternate]" />
            <div className="absolute top-1/2 right-10 w-80 h-80 bg-gradient-to-br from-emerald-100/10 via-teal-100/20 to-transparent blur-3xl rounded-full pointer-events-none animate-[pulse_10s_infinite_alternate_2s]" />

            {/* 0. Intro Video (Reduced from duration-700 to duration-400) */}
            <div
              data-section="intro"
              className={`relative overflow-hidden rounded-3xl mb-10 shadow-sm transition-all duration-400 ease-out ${
                visibleSections['intro'] ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'
              }`}
            >
              <video
                className="w-full h-[280px] md:h-[380px] object-cover object-top pointer-events-none md:pointer-events-auto"
                src="/videos/customer_support.mp4"
                autoPlay
                muted
                loop
                playsInline
                preload="auto"
              />
              <div className="absolute inset-0 bg-gradient-to-t from-black/60 via-black/10 to-transparent pointer-events-none" />
              <div className="absolute bottom-0 left-0 p-6 md:p-8 pointer-events-none">
                <h1 className="text-white text-xl md:text-2xl font-extrabold leading-tight">
                  Welcome to the Ticket Resolution System
                </h1>
                <p className="text-white/80 text-sm mt-1">
                  Here to help you raise, track, and resolve issues faster.
                </p>
              </div>
            </div>

            {/* 1. Dynamic Stats Grid */}
            <div 
              data-section="stats"
              className={`relative grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-10 transition-all duration-400 ease-out ${
                visibleSections['stats'] ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'
              }`}
            >
              <StatsCard label="Total Tickets" icon={Ticket} iconColor="text-neutral-900" value={data.total_tickets || 0} />
              <StatsCard label="Escalated" icon={Info} iconColor="text-rose-500" value={data.escalated || 0} />
              <StatsCard label="In Progress" icon={History} iconColor="text-amber-500" value={data.in_progress || 0} />
              <StatsCard label="Resolved" value={data.resolved || 0} icon={CheckCircle} iconColor="text-emerald-500" />
            </div>

            {/* 2. About Section (Reduced from duration-1000/delay-150 to duration-500/delay-75) */}
            <div 
              data-section="about"
              className={`relative overflow-hidden rounded-3xl bg-white border border-neutral-150 shadow-sm mb-10 transition-all duration-500 ease-out delay-75 ${
                visibleSections['about'] ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-6'
              }`}
            >
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-center p-8 lg:p-12">
                <div>
                  <h2 className="text-2xl lg:text-3xl font-extrabold text-neutral-900 mb-4 leading-tight">
                    The Ticket Resolution System, built for clarity and speed
                  </h2>
                  <p className="text-neutral-500 leading-relaxed text-sm mb-4">
                    TRS (Ticket Resolution System) helps you raise, track, and resolve issues
                    without the back-and-forth. Every ticket you submit is logged, routed to the
                    right team, and monitored end-to-end so nothing slips through the cracks.
                  </p>
                  <p className="text-neutral-500 leading-relaxed text-sm">
                    Whether it's a quick query or an escalated issue, TRS gives you full
                    visibility into status, history, and resolution — all from a single dashboard.
                  </p>

                  <div className="grid grid-cols-2 gap-4 mt-8">
                    <div className="flex items-start gap-3 group">
                      <div className="p-2 rounded-lg bg-indigo-50 text-indigo-600 group-hover:bg-indigo-600 group-hover:text-white transition-all duration-200">
                        <Clock size={18} />
                      </div>
                      <div>
                        <p className="text-sm font-bold text-neutral-900">Fast Turnaround</p>
                        <p className="text-xs text-neutral-400">Avg. resolution in hours</p>
                      </div>
                    </div>
                    <div className="flex items-start gap-3 group">
                      <div className="p-2 rounded-lg bg-emerald-50 text-emerald-600 group-hover:bg-emerald-600 group-hover:text-white transition-all duration-200">
                        <ShieldCheck size={18} />
                      </div>
                      <div>
                        <p className="text-sm font-bold text-neutral-900">Secure & Tracked</p>
                        <p className="text-xs text-neutral-400">Every action is logged</p>
                      </div>
                    </div>
                    <div className="flex items-start gap-3 group">
                      <div className="p-2 rounded-lg bg-amber-50 text-amber-600 group-hover:bg-amber-600 group-hover:text-white transition-all duration-200">
                        <Users size={18} />
                      </div>
                      <div>
                        <p className="text-sm font-bold text-neutral-900">Right Team</p>
                        <p className="text-xs text-neutral-400">Smart routing allocation</p>
                      </div>
                    </div>
                    <div className="flex items-start gap-3 group">
                      <div className="p-2 rounded-lg bg-purple-50 text-purple-600 group-hover:bg-purple-600 group-hover:text-white transition-all duration-200">
                        <BarChart3 size={18} />
                      </div>
                      <div>
                        <p className="text-sm font-bold text-neutral-900">Full Visibility</p>
                        <p className="text-xs text-neutral-400">Track journey endpoints</p>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="relative overflow-hidden rounded-2xl group">
                  <div className="absolute -inset-4 bg-gradient-to-tr from-indigo-100/40 to-neutral-200/30 rounded-3xl blur-2xl pointer-events-none" />
                  <img
                    src="https://res.cloudinary.com/dlfyesjsd/image/upload/v1784039660/krakenimages-376KN_ISplE-unsplash_aainm6.jpg"
                    alt="Support team collaborating"
                    className="relative rounded-2xl shadow-md w-full h-80 object-cover transition-transform duration-500 ease-out group-hover:scale-[1.02]"
                  />
                </div>
              </div>
            </div>

            {/* 3. Feature Highlight Grid (Reduced from duration-1000/delay-300 to duration-500/delay-150) */}
            <div 
              data-section="features"
              className={`grid grid-cols-1 md:grid-cols-3 gap-6 mb-4 transition-all duration-500 ease-out delay-150 ${
                visibleSections['features'] ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-6'
              }`}
            >
              {[
                {
                  img: 'https://res.cloudinary.com/dlfyesjsd/image/upload/v1784039791/next_one_for_trs_pcvusd.avif',
                  title: 'Raise Tickets Instantly',
                  desc: 'Submit a new ticket in seconds with clear categories and priority levels.',
                },
                {
                  img: 'https://res.cloudinary.com/dlfyesjsd/image/upload/v1784039830/trs_third_ekoytc.avif',
                  title: 'Track Every Step',
                  desc: 'Get real-time status updates from submission to resolution.',
                },
                {
                  img: 'https://res.cloudinary.com/dlfyesjsd/image/upload/v1784039866/trs_four_sfnc2f.avif',
                  title: 'Escalate When Needed',
                  desc: 'Critical issues get flagged and routed to senior support automatically.',
                },
              ].map((card, i) => (
                <div
                  key={i}
                  className="group rounded-2xl overflow-hidden border border-neutral-150 bg-white shadow-sm hover:shadow-md transition-all duration-300 hover:-translate-y-1"
                >
                  <div className="overflow-hidden h-40">
                    <img
                      src={card.img}
                      alt={card.title}
                      className="w-full h-full object-cover group-hover:scale-103 transition-transform duration-500 ease-out"
                    />
                  </div>
                  <div className="p-5">
                    <h3 className="font-bold text-neutral-900 mb-1 group-hover:text-indigo-600 transition-colors duration-200">{card.title}</h3>
                    <p className="text-sm text-neutral-500 leading-relaxed">{card.desc}</p>
                  </div>
                </div>
              ))}
            </div>
            

            {/* 4. Modular Footer Section */}
            <div 
              data-section="footer"
              className={`transition-all duration-500 ease-out delay-200 ${
                visibleSections['footer'] ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-6'
              }`}
            >
              <Footer />
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default UserDashboard;