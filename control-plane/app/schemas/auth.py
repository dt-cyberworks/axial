import uuid

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class LoginChallengeOut(BaseModel):
    status: str  # 'set_password' | 'mfa_enroll' | 'mfa_verify'
    challenge_id: uuid.UUID


class SetFirstPasswordIn(BaseModel):
    challenge_id: uuid.UUID
    new_password: str = Field(min_length=12)


class MfaEnrollIn(BaseModel):
    challenge_id: uuid.UUID


class MfaEnrollOut(BaseModel):
    challenge_id: uuid.UUID
    secret: str
    otpauth_uri: str


class MfaConfirmIn(BaseModel):
    challenge_id: uuid.UUID
    code: str


class MfaVerifyIn(BaseModel):
    challenge_id: uuid.UUID
    code: str


class SessionOut(BaseModel):
    user: "UserOut"
    backup_codes: list[str] | None = None


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    email: str
    display_name: str
    role: str
    status: str


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12)


class MfaReenrollStartIn(BaseModel):
    current_password: str


class MfaReenrollStartOut(BaseModel):
    secret: str
    otpauth_uri: str


class MfaReenrollConfirmIn(BaseModel):
    code: str


class MfaReenrollConfirmOut(BaseModel):
    backup_codes: list[str]


class SessionInfoOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    ip_address: str | None
    user_agent: str | None
    created_at: str
    last_seen_at: str
    is_current: bool = False


class AdminCreateUserIn(BaseModel):
    email: EmailStr
    display_name: str
    role: str = "operator"


class AdminCreateUserOut(BaseModel):
    user: UserOut
    temporary_password: str


class AdminUpdateUserIn(BaseModel):
    role: str | None = None
    status: str | None = None


class AdminResetPasswordOut(BaseModel):
    temporary_password: str
