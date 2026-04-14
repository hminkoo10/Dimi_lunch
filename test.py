import sys
import meal

if len(sys.argv) > 1 and sys.argv[1] in {"register-2fa", "--register-2fa"}:
    meal.register_two_factor_method()
else:
    meal.test_once(meal_key="breakfast", date_text="2026-04-15", upload=True)
