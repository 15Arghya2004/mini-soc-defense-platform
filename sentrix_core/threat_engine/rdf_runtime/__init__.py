import sys
from . import rdf_cache

# Register deprecated distributed_cache for backward compatibility
sys.modules['threat_engine.rdf_runtime.distributed_cache'] = rdf_cache
