from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import engine
import re

app = FastAPI(title="Wazuh Auto-Generator")
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request, log: str = None):
    return templates.TemplateResponse("index.html", {
        "request": request, 
        "xml_output": None, 
        "sim_data": None,
        "raw_log": log if log else ""
    })

@app.post("/generate", response_class=HTMLResponse)
async def generate_config(request: Request, raw_log: str = Form(...)):
    xml_result = engine.generate_wazuh_config(raw_log)
    
    sim_data = None
    try:
        regex_match = re.search(r'<regex[^>]*>(.*?)</regex>', xml_result, re.DOTALL)
        order_match = re.search(r'<order>(.*?)</order>', xml_result, re.DOTALL)
        
        if regex_match and order_match:
            gen_regex = regex_match.group(1).strip()
            order_list = [x.strip() for x in order_match.group(1).split(',')]
            order_list = [x for x in order_list if x]
            sim_data = engine.simulate_wazuh_extraction(raw_log, gen_regex, order_list)
    except Exception as e:
        print(f"[-] Simulation parsing error: {e}")
        sim_data = {"success": False, "error": f"Internal parsing error: {str(e)}"}

    return templates.TemplateResponse(
        "index.html", 
        {
            "request": request,
            "xml_output": xml_result,
            "raw_log": raw_log,
            "sim_data": sim_data
        }
    )

@app.get("/bulk", response_class=HTMLResponse)
async def bulk_page(request: Request):
    return templates.TemplateResponse("bulk.html", {
        "request": request,
        "results": None,
        "total_logs": 0
    })

@app.post("/bulk/analyze", response_class=HTMLResponse)
async def bulk_analyze(request: Request, bulk_logs: str = Form(...)):
    logs = bulk_logs.strip().split('\n')
    total_logs = len([l for l in logs if l.strip()])
    
    # Get top 3 patterns
    patterns = engine.analyze_log_batch(logs)
    
    # Calculate coverage
    covered = sum(p['count'] for p in patterns)
    coverage = (covered / total_logs * 100) if total_logs > 0 else 0
    
    return templates.TemplateResponse("bulk.html", {
        "request": request,
        "results": patterns,
        "total_logs": total_logs,
        "covered": covered,
        "coverage": round(coverage, 1)
    })