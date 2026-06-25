import os
import logging

logger = logging.getLogger("sentrix.investigation.markdown_exporter")

class MarkdownExporter:
    def export(self, template_path: str, replacements: dict, output_path: str) -> str:
        """
        Populates a Markdown template with values and saves the resulting document.
        
        Parameters:
            template_path : Path to the source template file
            replacements  : Dictionary mapping {{placeholder}} names to replacement strings
            output_path   : Path where the populated file will be written
            
        Returns:
            str: Path to the generated Markdown file
        """
        if not os.path.exists(template_path):
            raise FileNotFoundError(f"Source report template not found at {template_path}")

        try:
            # 1. Read template content
            with open(template_path, "r", encoding="utf-8") as f:
                content = f.read()

            # 2. Process all replacements
            for placeholder, value in replacements.items():
                target = "{{" + placeholder + "}}"
                content = content.replace(target, str(value))

            # 3. Ensure parent folders exist
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            # 4. Write populated content
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)

            logger.info(f"[MarkdownExporter] Successfully exported report to {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"[MarkdownExporter] Failed to compile Markdown: {e}")
            raise e
