import json
import os
import logging

logger = logging.getLogger("sentrix.investigation.json_exporter")

class JSONExporter:
    def export(self, payload: dict, output_path: str) -> str:
        """
        Exports the incident report payload as a JSON file.
        
        Parameters:
            payload     : dict containing the master report findings
            output_path : path where the file will be saved
            
        Returns:
            str: Path to the generated JSON file
        """
        try:
            # Ensure parent directories exist
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, default=str)
                
            logger.info(f"[JSONExporter] Successfully exported report to {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"[JSONExporter] Failed to export JSON: {e}")
            raise e
