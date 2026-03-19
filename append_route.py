def append_code():
    code = """
@router.post("/reset-password")
async def reset_password(payload: PasswordResetRequest, db: AsyncSession = Depends(get_db)):
    \"\"\"Reset a user's password using the server-side recovery key.\"\"\"
    if not settings.PASSWORD_RECOVERY_KEY:
        raise HTTPException(status_code=500, detail="Password recovery not configured on server")
        
    if not secrets.compare_digest(payload.recovery_key, settings.PASSWORD_RECOVERY_KEY):
        raise HTTPException(status_code=401, detail="Invalid recovery key")
        
    if payload.new_password != payload.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")
        
    # Get user
    result = await db.execute(select(User).where(User.username == payload.username))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    user.hashed_password = hash_password(payload.new_password)
    
    await record_audit(
        db, action="auth.password_reset", user_id=user.id, username=user.username,
        resource_type="auth", resource_id=user.id,
    )
    
    await db.commit()
    return {"detail": "Password reset successful"}
"""
    with open("ThreatLoom/threatloom/api/v1/users.py", "a", encoding="utf-8") as f:
        f.write(code)

if __name__ == "__main__":
    append_code()
