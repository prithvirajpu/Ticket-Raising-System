const SummaryCard = ({ summary }) => {

    if (!summary) return null;

    return (

        <div className="bg-white border rounded-xl p-5">

            <h3 className="text-lg font-bold mb-5">
                Summary
            </h3>

            <div className="grid md:grid-cols-2 gap-4">

                {Object.entries(summary).map(([key, value]) => (

                    <div
                        key={key}
                        className="border rounded-lg p-3"
                    >

                        <p className="text-xs uppercase text-gray-500">
                            {key.replaceAll("_", " ")}
                        </p>

                        <p className="font-semibold">

                            {typeof value === "boolean"
                                ? value
                                    ? "Yes"
                                    : "No"
                                : String(value)}

                        </p>

                    </div>

                ))}

            </div>

        </div>

    );

};

export default SummaryCard;