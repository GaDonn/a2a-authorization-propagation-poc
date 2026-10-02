import asyncio

from common.config import PATIENT_URL, REQUEST_AUTHENTICATION
from common.wire_client import send_message


async def main() -> None:
    response = await send_message(
        agent_url=PATIENT_URL,
        text="I want reimbursement for treatment T123.",
        metadata={},
        sender_id="reimbursement-client",
        receiver_id="patient-agent",
        sign_request=(
            REQUEST_AUTHENTICATION == "on"
        ),
    )

    print()
    print("FINAL RESPONSE")
    print("==============")
    print(response)


if __name__ == "__main__":
    asyncio.run(main())
