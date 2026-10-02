import os

import uvicorn

from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import AgentCapabilities, AgentCard, AgentInterface, AgentSkill

from patient_agent.agent_executor import PatientAgentExecutor


def build_app():
    port = int(os.getenv("PORT", "12000"))

    skill = AgentSkill(
        id="patient-reimbursement",
        name="Patient reimbursement request",
        description="Starts a reimbursement request.",
        tags=["healthcare", "patient", "reimbursement"],
        examples=["I want reimbursement for treatment T123."],
    )

    agent_card = AgentCard(
        name="Patient Agent",
        description="Patient-facing agent that initiates reimbursement workflows.",
        #url=f"http://127.0.0.1:{port}",
        version="0.1.0",
        default_input_modes=["text"],
        default_output_modes=["text"],
        capabilities=AgentCapabilities(streaming=False),
        supported_interfaces=[
            AgentInterface(
                protocol_binding="JSONRPC",
                url=f"http://127.0.0.1:{port}",
            )
        ],
        skills=[skill],
    )

    handler = DefaultRequestHandler(
        agent_executor=PatientAgentExecutor(),
        task_store=InMemoryTaskStore(),
    )

    return A2AStarletteApplication(
        agent_card=agent_card,
        http_handler=handler,
    ).build()


app = build_app()


if __name__ == "__main__":
    port = int(os.getenv("PORT", "12000"))
    uvicorn.run(app, host="127.0.0.1", port=port)