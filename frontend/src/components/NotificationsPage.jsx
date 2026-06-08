import { Bell, CheckCircle, AlertTriangle, X, PhoneMissed, MessageSquare, RefreshCw, UserPlus, Star } from "lucide-react";
import { useNotifications } from "../auth/NotificationProvider";
import { useState } from "react";

const NotificationPage = ({ isOpen, onClose }) => {
    const { 
        notifications, 
        unreadCount, 
        handleNotificationClick, 
        handleMarkAllRead 
    } = useNotifications();

    const getIcon = (type) => {
    switch (type) {
        case "MISSED_CALL":
            return (
                <div className="p-2 bg-rose-50 rounded-lg text-rose-600 border border-rose-100">
                    <PhoneMissed size={16} />
                </div>
            );
        case "TICKET_REVIEWED":
            return (
                <div className="p-2 bg-yellow-50 rounded-lg text-yellow-600 border border-yellow-100">
                    <Star size={16} />
                </div>
            );
        case "TICKET_ESCALATED":
            return (
                <div className="p-2 bg-amber-50 rounded-lg text-amber-600 border border-amber-100">
                    <AlertTriangle size={16} />
                </div>
            );
        case "TICKET_ASSIGNED":
            return (
                <div className="p-2 bg-blue-50 rounded-lg text-blue-600 border border-blue-100">
                    <Bell size={16} />
                </div>
            );
        case "TICKET_RESOLVED":
            return (
                <div className="p-2 bg-emerald-50 rounded-lg text-emerald-600 border border-emerald-100">
                    <CheckCircle size={16} />
                </div>
            );
        case "TICKET_REOPENED":
            return (
                <div className="p-2 bg-orange-50 rounded-lg text-orange-600 border border-orange-100">
                    <RefreshCw size={16} />
                </div>
            );
        // case "WELCOME_ACCOUNT_CREATED":
        //     return (
        //         <div className="p-2 bg-purple-50 rounded-lg text-purple-600 border border-purple-100">
        //             <UserPlus size={16} />
        //         </div>
        //     );
        case "CHAT_MESSAGE":
            return (
                <div className="p-2 bg-indigo-50 rounded-lg text-indigo-600 border border-indigo-100">
                    <MessageSquare size={16} />
                </div>
            );
        default:
            return (
                <div className="p-2 bg-slate-50 rounded-lg text-slate-600 border border-slate-100">
                    <Bell size={16} />
                </div>
            );
    }
};

    if (!isOpen) return null;

    return (
        <div className="absolute right-0 top-12 w-[400px] bg-white rounded-xl shadow-xl border border-slate-200/80 z-50 overflow-hidden flex flex-col max-h-[550px]">
            {/* Header */}
            <div className="flex justify-between items-center px-4 py-3.5 border-b border-slate-100">
                <div className="flex items-center gap-2">
                    <h2 className="font-semibold text-slate-900 text-base">
                        Notifications
                    </h2>
                    {unreadCount > 0 && (
                        <span className="px-2 py-0.5 text-xs font-semibold bg-blue-50 text-blue-600 rounded-full">
                            {unreadCount} new
                        </span>
                    )}
                </div>

                <button 
                    onClick={onClose}
                    className="p-1 rounded-lg text-slate-400 hover:bg-slate-50 hover:text-slate-600 transition-colors"
                >
                    <X size={16} />
                </button>
            </div>

            {/* Action Bar */}
            <div className="flex justify-between items-center px-4 py-2 bg-slate-50/60 border-b border-slate-100">
                <span className="text-xs font-medium text-slate-500">
                    {unreadCount} unread
                </span>

                <button
                    onClick={handleMarkAllRead}
                    className="text-xs font-medium text-blue-600 hover:text-blue-700 transition-colors"
                >
                    Mark all read
                </button>
            </div>

            {/* Notification List Container */}
            <div className="divide-y divide-slate-100 overflow-y-auto flex-1">
                {notifications.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-12 px-4 text-center">
                        <div className="p-3 bg-slate-50 rounded-full text-slate-400 mb-2">
                            <Bell size={20} />
                        </div>
                        <p className="text-sm font-medium text-slate-900">All caught up!</p>
                        <p className="text-xs text-slate-500 mt-0.5">No notifications yet</p>
                    </div>
                ) : (
                    notifications.map((notification) => (
                        
                        <div
                            key={notification.id}
                            onClick={() => handleNotificationClick(notification)}
                            className={`p-4 transition-all duration-200 cursor-pointer flex gap-3 items-start select-none ${
                                !notification.is_read
                                    ? "bg-blue-50/40 hover:bg-blue-50/70"
                                    : "bg-white hover:bg-slate-50"
                            }`}
                        >
                            {console.log(notification)}
                            {/* Icon Wrapper */}
                            <div className="flex-shrink-0">
                                {getIcon(notification.notification_type)}
                            </div>

                            {/* Content Body */}
                            <div className="flex-1 min-w-0">
                                <div className="flex justify-between items-start gap-2">
                                    <h3
                                        className={`text-sm leading-tight text-slate-900 break-words ${
                                            !notification.is_read ? "font-semibold" : "font-normal"
                                        }`}
                                    >
                                        {notification.title}
                                    </h3>

                                    {/* Unread indicator dot */}
                                    {!notification.is_read && (
                                        <div className="w-2 h-2 rounded-full bg-blue-500 flex-shrink-0 mt-1.5" />
                                    )}
                                </div>

                                <p className="text-xs text-slate-600 mt-1 leading-relaxed break-words">
                                    {notification.message}
                                </p>

                                {/* Meta section container */}
                                <div className="mt-2.5 flex items-center gap-2.5 flex-wrap">

                                    {notification.data?.ticket_id && (
                                        <span className="inline-flex items-center font-medium text-[11px] px-1.5 py-0.5 bg-slate-100 text-slate-700 rounded">
                                            Ticket #{notification.data.ticket_code}
                                        </span>
                                    )}
                                    <span className="text-[11px] text-slate-400">
                                        {notification.created_at}
                                    </span>
                                </div>
                            </div>
                        </div>
                    ))
                )}
            </div>
        </div>
    );
};

export default NotificationPage;