from supabase import create_client, Client
from src.config.config import settings
from src.logging.logger import logger

class SupabaseManager:
    """
    Manages Supabase PostgreSQL and Storage client connections.
    """
    _client: Client = None

    @classmethod
    def get_client(cls) -> Client:
        if cls._client is None:
            try:
                cls._client = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)
                logger.info("Supabase client initialized successfully")
            except Exception as e:
                logger.error("Failed to initialize Supabase client", extra_data={"error": str(e)})
                raise e
        return cls._client

supabase_client = SupabaseManager.get_client()
