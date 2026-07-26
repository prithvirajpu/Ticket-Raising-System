import React from 'react';
import { Link } from 'react-router-dom';
import { Ticket, Mail, Phone, MapPin, ArrowUpRight, Github, Linkedin, Twitter } from 'lucide-react';

const Footer = () => {
  return (
    <footer className="relative mt-24 w-full bg-neutral-100 border-t border-neutral-200/60 font-sans overflow-hidden">
      {/* Structural Engineering Grid Context */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#8080800a_1px,transparent_1px),linear-gradient(to_bottom,#8080800a_1px,transparent_1px)] bg-[size:24px_24px] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] pointer-events-none" />
      
      {/* Ambient Emerald Accent Hub */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 -translate-y-1/2 w-72 h-20 bg-emerald-500/10 blur-[60px] rounded-full pointer-events-none" />

      <div className="relative max-w-7xl mx-auto px-6 sm:px-8 pt-16 pb-10">
        
        {/* Main Content Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-12 gap-10 lg:gap-8 pb-12 border-b border-neutral-200/60">
          
          {/* Brand Column */}
          <div className="lg:col-span-5 space-y-4">
            <Link to="/" className="inline-flex items-center gap-2.5 group">
              <div className="p-2 bg-white text-emerald-600 rounded-xl shadow-[0_2px_8px_rgba(0,0,0,0.04)] border border-neutral-200/80 transition-all duration-300 group-hover:bg-emerald-600 group-hover:text-white group-hover:scale-105">
                <Ticket size={18} strokeWidth={2.5} />
              </div>
              <span className="text-neutral-900 font-bold text-xl tracking-tight transition-colors group-hover:text-emerald-600">
                TicketFlow
              </span>
            </Link>
            <p className="text-sm text-neutral-500 leading-relaxed max-w-sm">
              An enterprise-grade Ticket Resolution System engineering frictionless issue tracking, absolute operational clarity, and high-velocity workflows.
            </p>
            
            {/* Social Accounts */}
            <div className="flex items-center gap-2.5 pt-2">
              <a href="#" className="p-2 rounded-lg bg-white border border-neutral-200/80 text-neutral-400 hover:text-neutral-900 hover:border-neutral-400 hover:shadow-sm transition-all duration-200">
                <Twitter size={15} />
              </a>
              <a href="#" className="p-2 rounded-lg bg-white border border-neutral-200/80 text-neutral-400 hover:text-neutral-900 hover:border-neutral-400 hover:shadow-sm transition-all duration-200">
                <Linkedin size={15} />
              </a>
              <a href="#" className="p-2 rounded-lg bg-white border border-neutral-200/80 text-neutral-400 hover:text-neutral-900 hover:border-neutral-400 hover:shadow-sm transition-all duration-200">
                <Github size={15} />
              </a>
            </div>
          </div>
          
          {/* Quick Actions Column */}
          <div className="lg:col-span-3 space-y-4">
            <h4 className="text-neutral-900 font-semibold text-xs tracking-wider uppercase">Portal Navigation</h4>
            <ul className="space-y-3 text-sm">
              <li>
                <Link to="/user/create-ticket" className="inline-flex items-center gap-1 text-neutral-500 hover:text-emerald-600 font-medium transition-colors duration-200 group">
                  Raise New Ticket 
                  <ArrowUpRight size={14} className="opacity-0 -translate-y-0.5 -translate-x-0.5 group-hover:opacity-100 group-hover:translate-x-0 group-hover:translate-y-0 transition-all duration-200" />
                </Link>
              </li>
              <li>
                <Link to="/user/tickets" className="text-neutral-500 hover:text-neutral-900 transition-colors duration-200">
                  My Active Tickets
                </Link>
              </li>
              <li>
                <Link to="/user/dashboard" className="text-neutral-500 hover:text-neutral-900 transition-colors duration-200">
                  Control Dashboard
                </Link>
              </li>
            </ul>
          </div>
          
          {/* Contact Support Column */}
          <div className="lg:col-span-4 space-y-4">
            <h4 className="text-neutral-900 font-semibold text-xs tracking-wider uppercase">Contact Channels</h4>
            <ul className="space-y-3 text-sm">
              <li>
                <a href="mailto:pythondevelopment10@gmaill.com" className="flex items-center gap-3 text-neutral-500 hover:text-neutral-900 transition-colors duration-200 group">
                  <div className="p-1.5 bg-white border border-neutral-200 rounded-lg group-hover:border-emerald-200 group-hover:bg-emerald-50/30 transition-colors">
                    <Mail size={14} className="text-neutral-400 group-hover:text-emerald-600" />
                  </div>
                  pythondevelopment10@gmaill.com
                </a>
              </li>
              <li>
                <a href="tel:+919876543210" className="flex items-center gap-3 text-neutral-500 hover:text-neutral-900 transition-colors duration-200 group">
                  <div className="p-1.5 bg-white border border-neutral-200 rounded-lg group-hover:border-emerald-200 group-hover:bg-emerald-50/30 transition-colors">
                    <Phone size={14} className="text-neutral-400 group-hover:text-emerald-600" />
                  </div>
                  +91 9072513338
                </a>
              </li>
              <li className="flex items-center gap-3 text-neutral-500">
                <div className="p-1.5 bg-white border border-neutral-200 rounded-lg">
                  <MapPin size={14} className="text-neutral-400" />
                </div>
                <span>Kerala, India</span>
              </li>
            </ul>
          </div>

        </div>
        
        {/* Bottom Utility Bar */}
        <div className="relative pt-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-neutral-400 font-medium">
          <div>
            © {new Date().getFullYear()} TicketFlow Systems. All rights reserved.
          </div>
          <div className="flex items-center gap-6">
            <a href="#" className="hover:text-neutral-600 transition-colors">Privacy Policy</a>
            <a href="#" className="hover:text-neutral-600 transition-colors">Terms of Service</a>
            <a href="#" className="hover:text-neutral-600 transition-colors">SLA Agreement</a>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;