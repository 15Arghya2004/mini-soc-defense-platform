import os
import logging
from datetime import datetime

logger = logging.getLogger("sentrix.investigation.pdf_exporter")

class PDFExporter:
    def export(self, payload: dict, output_path: str) -> str:
        """
        Generates a valid, multi-page PDF report using pure Python byte assembly.
        No external reportlab or weasyprint required.
        """
        try:
            # 1. Gather text content to print
            text_lines = []
            self._add_header_info(payload, text_lines)
            self._add_executive_summary(payload, text_lines)
            self._add_attack_timeline(payload, text_lines)
            self._add_attack_chain(payload, text_lines)
            self._add_mitre_mapping(payload, text_lines)
            self._add_layer_trace(payload, text_lines)
            self._add_recommendations(payload, text_lines)

            # 2. Paginate text lines (A4 has ~50 lines per page with 15pt spacing)
            lines_per_page = 45
            pages_data = []
            current_page = []
            
            for line, is_bold in text_lines:
                current_page.append((line, is_bold))
                if len(current_page) >= lines_per_page:
                    pages_data.append(current_page)
                    current_page = []
            if current_page:
                pages_data.append(current_page)

            # 3. Assemble PDF byte stream objects
            pdf_bytes = self._assemble_pdf_bytes(payload.get("incident_id"), pages_data)

            # 4. Save file
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "wb") as f:
                f.write(pdf_bytes)

            logger.info(f"[PDFExporter] Successfully exported PDF report to {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"[PDFExporter] Failed to compile PDF: {e}")
            raise e

    def _wrap_text(self, text: str, max_chars: int = 75) -> list:
        wrapped = []
        for line in text.split("\n"):
            words = line.split(" ")
            curr = ""
            for w in words:
                if len(curr) + len(w) + 1 > max_chars:
                    wrapped.append(curr)
                    curr = w
                else:
                    curr = (curr + " " + w) if curr else w
            if curr:
                wrapped.append(curr)
        return wrapped

    def _add_header_info(self, payload: dict, lines: list):
        lines.append(("SENTRIX CASE INTELLIGENCE REPORT", True))
        lines.append(("===================================", False))
        lines.append((f"Incident ID      : {payload.get('incident_id')}", False))
        lines.append((f"Severity         : {payload.get('severity', 'LOW').upper()}", False))
        lines.append((f"Source IP        : {payload.get('source_ip')}", False))
        lines.append((f"Target Host      : {payload.get('destination_host', 'unknown')}", False))
        lines.append((f"Case Status      : {payload.get('case_status', 'OPEN')}", False))
        lines.append((f"Assigned Analyst : {payload.get('assigned_analyst')}", False))
        lines.append(("", False))

    def _add_executive_summary(self, payload: dict, lines: list):
        from sentrix_core.investigation_engine.reporting.executive_summary import ExecutiveSummaryFormatter
        summary_text = ExecutiveSummaryFormatter().format(payload)
        lines.append(("EXECUTIVE BRIEF SUMMARY", True))
        lines.append(("-----------------------", False))
        for wrapped_line in self._wrap_text(summary_text):
            lines.append((wrapped_line, False))
        lines.append(("", False))

    def _add_attack_timeline(self, payload: dict, lines: list):
        lines.append(("CHRONOLOGICAL ATTACK TIMELINE", True))
        lines.append(("------------------------------", False))
        timeline = payload.get("timeline", [])
        if not timeline:
            lines.append(("* No alerts mapped on timeline *", False))
        else:
            for ev in timeline:
                line_str = f"[{ev.get('time_display')}] {ev.get('rule_name')} (Risk: {ev.get('risk_score')}/100) -> Action: {ev.get('response_action')}"
                for wrapped in self._wrap_text(line_str):
                    lines.append((wrapped, False))
        lines.append(("", False))

    def _add_attack_chain(self, payload: dict, lines: list):
        lines.append(("RECONSTRUCTED ATTACK CHAIN", True))
        lines.append(("---------------------------", False))
        chain = payload.get("attack_chain", {})
        graph = chain.get("graph_text", "N/A")
        lines.append((graph, False))
        lines.append(("", False))

    def _add_mitre_mapping(self, payload: dict, lines: list):
        lines.append(("MITRE ATT&CK MATRIX MAPPING", True))
        lines.append(("----------------------------", False))
        mitre = payload.get("mitre_mapping", {})
        lines.append((f"Matrix Coverage : {mitre.get('matrix_coverage_percentage', 0)}%", False))
        lines.append((f"Observed Tactics: {', '.join(mitre.get('mapped_stages', []))}", False))
        lines.append((f"Technique Codes : {', '.join(mitre.get('mapped_techniques', []))}", False))
        lines.append(("", False))

    def _add_layer_trace(self, payload: dict, lines: list):
        from sentrix_core.investigation_engine.reporting.layer_trace_report import LayerTraceReportFormatter
        traces = LayerTraceReportFormatter().format(payload.get("layer_trace", {}))
        
        lines.append(("THREAT ENGINE PIPELINE LAYER TRACEABILITY", True))
        lines.append(("-----------------------------------------", False))
        
        layers = ["detection", "correlation", "context", "campaign", "prediction", "response"]
        for layer in layers:
            content = traces.get(layer, "")
            lines.append((f"-> {layer.upper()} LAYER", True))
            for line in content.split("\n"):
                if line.startswith("- ") or line.startswith("**"):
                    clean = line.replace("**", "").replace("- ", "  * ")
                    for wrapped in self._wrap_text(clean):
                        lines.append((wrapped, False))
            lines.append(("", False))

    def _add_recommendations(self, payload: dict, lines: list):
        from sentrix_core.investigation_engine.reporting.recommendation_report import RecommendationReportFormatter
        recommends = RecommendationReportFormatter().format(payload.get("response_findings", {}))
        lines.append(("CONTAINMENT PLAYBOOKS & REMEDIATION", True))
        lines.append(("-----------------------------------", False))
        for line in recommends.split("\n"):
            clean = line.replace("###", "").replace("####", "").replace("- **", "").replace("**", "")
            if clean.strip():
                for wrapped in self._wrap_text(clean):
                    lines.append((wrapped, False))

    def _assemble_pdf_bytes(self, incident_id: str, pages_data: list) -> bytes:
        """
        Assembles PDF document objects and cross-references.
        """
        # PDF Byte writer state
        objects = []
        
        # Helper to register pdf object definition
        def add_obj(data_bytes: bytes) -> int:
            objects.append(data_bytes)
            return len(objects)

        # 1. catalog (Object 1) - reference to pages collection (Object 2)
        catalog_id = 1
        
        # We will define the objects sequentially. Let's reserve IDs.
        # Catalog is Object 1. Pages collection is Object 2.
        # Font resources shared dict is Object 3.
        # Helvetica regular is Object 4.
        # Helvetica bold is Object 5.
        # Page Objects start at Object 6.
        
        pages_count = len(pages_data)
        page_object_ids = []
        for i in range(pages_count):
            page_object_ids.append(6 + 2 * i) # page object references
            
        # Object 1: Catalog
        add_obj(b"<< /Type /Catalog /Pages 2 0 R >>")
        
        # Object 2: Pages Collection
        kids_ref = " ".join(f"{pid} 0 R" for pid in page_object_ids)
        add_obj(f"<< /Type /Pages /Kids [{kids_ref}] /Count {pages_count} >>".encode("ascii"))
        
        # Object 3: Font Resources Dict
        add_obj(b"<< /Font << /F1 4 0 R /F2 5 0 R >> >>")
        
        # Object 4: Font F1 (Helvetica Regular)
        add_obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        
        # Object 5: Font F2 (Helvetica Bold)
        add_obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")

        # Object 6 & up: Page nodes and contents stream objects
        for page_idx, page_lines in enumerate(pages_data):
            page_obj_id = 6 + 2 * page_idx
            contents_obj_id = page_obj_id + 1
            
            # Write page node
            add_obj(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents {contents_obj_id} 0 R /Resources 3 0 R >>".encode("ascii"))
            
            # Compile contents stream for this page
            stream_body = b"BT\n/F1 10 Tf\n14 TL\n50 780 Td\n"
            y_pos = 780
            
            # Print page number header
            stream_body += f"/F2 9 Tf\n450 0 Td\n(Page {page_idx + 1} of {pages_count}) Tj\n-450 -20 Td\n/F1 10 Tf\n".encode("ascii")
            y_pos -= 20

            for line_text, is_bold in page_lines:
                # Sanitize text formatting for PDF strings (escape parentheses)
                escaped_text = line_text.replace("(", "\\(").replace(")", "\\)")
                
                font = "F2" if is_bold else "F1"
                font_size = "11" if is_bold else "10"
                
                # Render text line in PDF
                stream_body += f"/{font} {font_size} Tf\n({escaped_text}) Tj\n0 -15 Td\n".encode("ascii")
                y_pos -= 15

            stream_body += b"ET\n"
            
            # Write contents stream object
            add_obj(f"<< /Length {len(stream_body)} >>\nstream\n".encode("ascii") + stream_body + b"\nendstream")

        # 4. Generate byte compile output
        pdf_bytes = b"%PDF-1.4\n"
        offsets = {}
        for idx, obj in enumerate(objects):
            obj_id = idx + 1
            offsets[obj_id] = len(pdf_bytes)
            pdf_bytes += f"{obj_id} 0 obj\n".encode("ascii") + obj + b"\nendobj\n"
            
        xref_offset = len(pdf_bytes)
        pdf_bytes += b"xref\n"
        pdf_bytes += f"0 {len(objects) + 1}\n".encode("ascii")
        pdf_bytes += b"0000000000 65535 f \n"
        for obj_id in range(1, len(objects) + 1):
            pdf_bytes += f"{offsets[obj_id]:010d} 00000 n \n".encode("ascii")
            
        pdf_bytes += b"trailer\n"
        pdf_bytes += f"<< /Size {len(objects) + 1} /Root 1 0 R >>\n".encode("ascii")
        pdf_bytes += b"startxref\n"
        pdf_bytes += f"{xref_offset}\n".encode("ascii")
        pdf_bytes += b"%%EOF\n"
        
        return pdf_bytes
