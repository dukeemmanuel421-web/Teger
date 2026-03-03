from pydantic import BaseModel


class CreditInquiryResponse(BaseModel):
    ok: bool
    data: dict
    mode: str
