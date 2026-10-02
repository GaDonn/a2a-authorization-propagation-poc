import os

import uvicorn

from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import AgentCapabilities, AgentCard, AgentInterface, AgentSkill

from common.a2a_secure_passport_v1 import (
    secure_passport_extension_declaration,
)
from common.extended_secure_passport import (
    extended_secure_passport_extension_declaration,
)

from hospital_agent.agent_executor import HospitalAgentExecutor


def build_app():
    port = int(os.getenv("PORT", "12001"))

    skill = AgentSkill(
        id="hospital-validation",
        name="Hospital validation",
        description="Validates medical treatment information and forwards to insurance.",
        tags=["healthcare", "hospital", "validation"],
        examples=["Validate treatment T123."],
    )

    agent_card = AgentCard(
        name="Hospital Agent",
        description="Hospital agent that validates treatment information.",
        #url=f"http://127.0.0.1:{port}",
        version="0.1.0",
        default_input_modes=["text"],
        default_output_modes=["text"],
        capabilities=AgentCapabilities(
            streaming=False,
            extensions=[
                secure_passport_extension_declaration(
                    supported_state_keys=[
                    'patient_id',
                    'patient_reference',
                    'coverage_reference',
                    'claim_reference',
                    'insurance_plan',
                    'consent',
                    ],
                ),
                extended_secure_passport_extension_declaration(),
            ],
        ),
        supported_interfaces=[
            AgentInterface(
                protocol_binding="JSONRPC",
                url=f"http://127.0.0.1:{port}",
            )
        ],
        skills=[skill],
    )

    handler = DefaultRequestHandler(
        agent_executor=HospitalAgentExecutor(),
        task_store=InMemoryTaskStore(),
    )

    return A2AStarletteApplication(
        agent_card=agent_card,
        http_handler=handler,
    ).build()


app = build_app()


if __name__ == "__main__":
    port = int(os.getenv("PORT", "12001"))
    uvicorn.run(app, host="127.0.0.1", port=port)