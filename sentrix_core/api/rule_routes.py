from fastapi import APIRouter, Depends, Request, HTTPException
from pydantic import BaseModel
from typing import Dict, Any
from sentrix_core.security.auth import require_admin, require_soc_analyst

router = APIRouter(tags=["Rules"])

class RulePayload(BaseModel):
    rule: Dict[str, Any]

class TestPayload(BaseModel):
    rule: Dict[str, Any]
    event: Dict[str, Any]

@router.get("/")
async def list_rules(request: Request):
    rule_studio = getattr(request.app.state.engines, "rule_studio", None)
    if not rule_studio:
        raise HTTPException(status_code=503, detail="Rule Studio offline")
    return rule_studio.list_rules()

@router.post("/")
async def create_rule(request: Request, payload: RulePayload):
    rule_studio = getattr(request.app.state.engines, "rule_studio", None)
    if not rule_studio:
        raise HTTPException(status_code=503, detail="Rule Studio offline")
    try:
        return rule_studio.create_rule(payload.rule)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/{rule_id}")
async def get_rule(request: Request, rule_id: str):
    rule_studio = getattr(request.app.state.engines, "rule_studio", None)
    if not rule_studio:
        raise HTTPException(status_code=503, detail="Rule Studio offline")
    rule = rule_studio.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule

@router.put("/{rule_id}")
async def update_rule(request: Request, rule_id: str, payload: RulePayload):
    rule_studio = getattr(request.app.state.engines, "rule_studio", None)
    if not rule_studio:
        raise HTTPException(status_code=503, detail="Rule Studio offline")
    try:
        return rule_studio.update_rule(rule_id, payload.rule)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.delete("/{rule_id}")
async def delete_rule(request: Request, rule_id: str):
    rule_studio = getattr(request.app.state.engines, "rule_studio", None)
    if not rule_studio:
        raise HTTPException(status_code=503, detail="Rule Studio offline")
    if rule_studio.delete_rule(rule_id):
        return {"status": "success", "message": f"Rule {rule_id} deleted."}
    raise HTTPException(status_code=404, detail="Rule not found")

@router.post("/test")
async def test_rule(request: Request, payload: TestPayload):
    tester = getattr(request.app.state.engines, "rule_tester", None)
    if not tester:
        raise HTTPException(status_code=503, detail="Rule Tester offline")
    return tester.test_rule(payload.rule, payload.event)
