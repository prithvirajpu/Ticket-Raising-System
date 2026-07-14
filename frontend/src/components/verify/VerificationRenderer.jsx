import OrderIssueDetails from "./OrderIssueDetails";
import PaymentIssueDetails from "./PaymentIssueDetails";
import DeliveryIssueDetails from "./DeliveryIssueDetails";
import WalletIssueDetails from "./WalletIssueDetails";

const VerificationRenderer = ({ issueType, data }) => {

    if (!data) return null;

    switch (issueType) {

        case "ORDER_ISSUE":
            return <OrderIssueDetails data={data} />;

        case "PAYMENT_ISSUE":
            return <PaymentIssueDetails data={data} />;

        case "DELIVERY_ISSUE":
            return <DeliveryIssueDetails data={data} />;

        case "WALLET_ISSUE":
            return <WalletIssueDetails data={data} />;

        default:
            return null;

    }

};

export default VerificationRenderer;