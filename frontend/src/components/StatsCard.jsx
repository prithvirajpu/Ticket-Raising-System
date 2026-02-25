
const StatsCard = ({ label, value,subtext,icon:Icon,iconColor }) => {

  return (
    <div className="border border-gray-200 rounded-2xl p-6 flex flex-col justify-between h-40 bg-white">
      <div className="flex justify-between items-start">
        <span className="text-sm font-semibold text-gray-800">{label}</span>
        {Icon && <Icon className={`w-5 h-5 ${iconColor}`} />}
      </div>
      <div>
        <div className="text-3xl font-bold text-black">{value}</div>
        <div className="text-[10px] text-gray-400 mt-1">{subtext}</div>
      </div>
    </div>
  );
};

export default StatsCard;
