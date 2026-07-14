import React, { useEffect, useState, useRef } from 'react';
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

const UserDashboard = () => {
  const [data, setData] = useState({});
  const [animate, setAnimate] = useState(false);
  const [visibleSections, setVisibleSections] = useState({});
  const containerRef = useRef(null);
  const navigate = useNavigate();

  // 3D Parallax mouse tracking state
  const [tilt, setTilt] = useState({ x: 0, y: 0 });

  useEffect(() => {
    fetchData();
    
    // Trigger entrance animation for main frame
    const animFrame = requestAnimationFrame(() => {
      const timer = setTimeout(() => setAnimate(true), 100);
      return () => clearTimeout(timer);
    });

    // Intersection Observer for staggered scroll entry of child sections
    const observerOptions = {
      root: null,
      threshold: 0.1,
      rootMargin: "0px 0px -50px 0px"
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

  // 3D Perspective Mouse Move Handler (Stripe Premium Interaction)
  const handleMouseMove = (e) => {
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    
    // Calculate mouse position relative to the center of the element
    const width = rect.width;
    const height = rect.height;
    const mouseX = e.clientX - rect.left - width / 2;
    const mouseY = e.clientY - rect.top - height / 2;

    // Constrain the rotation angles to keep it extremely subtle and premium
    const rX = -(mouseY / height) * 4; // max tilt 2 degrees
    const rY = (mouseX / width) * 4;

    setTilt({ x: rX, y: rY });
  };

  const handleMouseLeave = () => {
    // Smoothly spring back to flat on mouse exit
    setTilt({ x: 0, y: 0 });
  };

  return (
    <DashboardLayout title="Dashboard" subtitle="Manage your assigned tickets">
      {/* Top Header Button with magnetic dynamic hover feedback */}
      <div className="flex justify-end mb-8 -mt-16">
        <button
          onClick={() => navigate('/user/create-ticket')}
          className="group relative flex items-center gap-2 bg-neutral-950 text-white px-5 py-2.5 rounded-xl hover:bg-black transition-all text-sm font-bold shadow-md hover:shadow-neutral-200/15 active:scale-95 duration-300"
        >
          <Plus size={18} className="transition-transform group-hover:rotate-90 duration-300 ease-out" />
          <span>Raise New Ticket</span>
        </button>
      </div>

      {/* Main Perspective Showcase Frame */}
      <div 
        ref={containerRef}
        onMouseMove={handleMouseMove}
        onMouseLeave={handleMouseLeave}
        className="transition-all duration-700 ease-out transform-gpu will-change-transform"
        style={{
          transform: animate 
            ? `perspective(1500px) rotateX(${tilt.x}deg) rotateY(${tilt.y}deg) scale(1)` 
            : 'perspective(1500px) rotateX(6deg) scale(0.96)',
          opacity: animate ? 1 : 0
        }}
      >
        {/* Modern Bento Container with subtle ambient backdrop highlights */}
        <div className="relative rounded-3xl border border-neutral-200/60 bg-neutral-50/40 p-6 md:p-8 overflow-hidden shadow-sm">
          
          {/* Drifting Ambient Spotlights in Background */}
          <div className="absolute top-0 left-1/4 w-96 h-96 bg-gradient-to-tr from-sky-200/20 via-indigo-100/30 to-violet-200/20 blur-3xl rounded-full pointer-events-none animate-[pulse_8s_infinite_alternate]" />
          <div className="absolute top-1/2 right-10 w-80 h-80 bg-gradient-to-br from-emerald-100/10 via-teal-100/20 to-transparent blur-3xl rounded-full pointer-events-none animate-[pulse_10s_infinite_alternate_2s]" />

          {/* 1. Dynamic Stats Grid - Staggered Scroll Slide Up */}
          <div 
            data-section="stats"
            className={`relative grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-10 transition-all duration-700 transform-gpu ${
              visibleSections['stats'] ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'
            }`}
          >
            <StatsCard label="Total Tickets" icon={Ticket} iconColor="text-neutral-900" value={data.total_tickets || 0} />
            <StatsCard label="Escalated" icon={Info} iconColor="text-rose-500" value={data.escalated || 0} />
            <StatsCard label="In Progress" icon={History} iconColor="text-amber-500" value={data.in_progress || 0} />
            <StatsCard label="Resolved" value={data.resolved || 0} icon={CheckCircle} iconColor="text-emerald-500" />
          </div>

          {/* 2. About / TRS Info Banner Section - Staggered Slide-Up */}
          <div 
            data-section="about"
            className={`relative overflow-hidden rounded-3xl bg-white border border-neutral-150 shadow-sm mb-10 transition-all duration-1000 delay-150 transform-gpu ${
              visibleSections['about'] ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-12'
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

                {/* Staggered features list on hover */}
                <div className="grid grid-cols-2 gap-4 mt-8">
                  <div className="flex items-start gap-3 group">
                    <div className="p-2 rounded-lg bg-indigo-50 text-indigo-600 group-hover:bg-indigo-600 group-hover:text-white transition-all duration-300">
                      <Clock size={18} />
                    </div>
                    <div>
                      <p className="text-sm font-bold text-neutral-900">Fast Turnaround</p>
                      <p className="text-xs text-neutral-400">Avg. resolution in hours</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3 group">
                    <div className="p-2 rounded-lg bg-emerald-50 text-emerald-600 group-hover:bg-emerald-600 group-hover:text-white transition-all duration-300">
                      <ShieldCheck size={18} />
                    </div>
                    <div>
                      <p className="text-sm font-bold text-neutral-900">Secure & Tracked</p>
                      <p className="text-xs text-neutral-400">Every action is logged</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3 group">
                    <div className="p-2 rounded-lg bg-amber-50 text-amber-600 group-hover:bg-amber-600 group-hover:text-white transition-all duration-300">
                      <Users size={18} />
                    </div>
                    <div>
                      <p className="text-sm font-bold text-neutral-900">Right Team</p>
                      <p className="text-xs text-neutral-400">Smart routing allocation</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3 group">
                    <div className="p-2 rounded-lg bg-purple-50 text-purple-600 group-hover:bg-purple-600 group-hover:text-white transition-all duration-300">
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
                  className="relative rounded-2xl shadow-md w-full h-80 object-cover transition-transform duration-1000 ease-out group-hover:scale-[1.035]"
                />
              </div>
            </div>
          </div>

          {/* 3. Feature Highlight Grid - Staggered entrance */}
          <div 
            data-section="features"
            className={`grid grid-cols-1 md:grid-cols-3 gap-6 mb-4 transition-all duration-1000 delay-300 transform-gpu ${
              visibleSections['features'] ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-12'
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
                className="group rounded-2xl overflow-hidden border border-neutral-150 bg-white shadow-sm hover:shadow-lg transition-all duration-500 hover:-translate-y-1.5"
              >
                <div className="overflow-hidden h-40">
                  <img
                    src={card.img}
                    alt={card.title}
                    className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-700 ease-out"
                  />
                </div>
                <div className="p-5">
                  <h3 className="font-bold text-neutral-900 mb-1 group-hover:text-indigo-600 transition-colors duration-300">{card.title}</h3>
                  <p className="text-sm text-neutral-500 leading-relaxed">{card.desc}</p>
                </div>
              </div>
            ))}
          </div>

          {/* 4. Modular Footer Section */}
          <div 
            data-section="footer"
            className={`transition-all duration-1000 delay-500 transform-gpu ${
              visibleSections['footer'] ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-12'
            }`}
          >
            <Footer />
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default UserDashboard;