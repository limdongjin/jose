# Python JWT 재구현 개요

이 디렉토리는 기존 TypeScript 구현을 참고하여 Python으로 JWT 기능을 재구현하기 위한 문서와 코드가 위치할 곳이다. TypeScript 쪽 코드는 변경하지 않고, Python 전용 파일만 `python/` 아래에 추가한다.

## 목표

- 기존 TypeScript 구현의 기능/행동을 최대한 동일하게 재현한다.
- API 설계는 Python 관례(타입 힌트, 예외 타입, 문서화)에 맞추되 TS와의 일대일 매핑이 가능한 구조를 유지한다.
- 테스트는 명세 기반(알고리즘/클레임/에러 처리)으로 구성해 TS 구현과의 호환성을 검증한다.

## 기본 가정

- 표준 JOSE/JWT 스펙을 준수한다.
- 안전한 기본값과 엄격한 검증(시간/클레임 타입/헤더)을 유지한다.
- 외부 의존성은 최소화하되, 검증된 암호 라이브러리를 사용한다.

## 디렉토리 구조

```
python/
  README.md
  PLAN.md
  src/
    jwt/
      __init__.py
      algorithms.py
      claims.py
      keys.py
      token.py
      errors.py
      utils.py
  doc/
    implementation-notes.md
  tests/
    test_algorithms.py
    test_claims.py
    test_tokens.py
    test_compat.py
```

## 문서화 계획

- `README.md`: 프로젝트 목적/설계 개요/사용 예시
- `PLAN.md`: 구현 단계와 세부 작업 목록
- 각 모듈 docstring 및 타입 힌트로 API 명세 제공

## 프로젝트 가이드라인

- Python 변경 사항은 항상 TypeScript 구현과의 대응 관계를 확인하고,
  참고한 TS 코드(파일/스니펫)를 `python/doc` 문서에 인용으로 남긴다.
- 기능 변경 시 `python/doc/release-notes.md`에 릴리즈 노트 스타일로 기록한다.
- 작업 범위나 진행 상황이 변경되면 `python/PLAN.md`를 함께 업데이트한다.
- TypeScript 패키지의 공개 API/에러 모델/옵션 동작과의 1:1 매핑을 우선하며,
  Python 관례로 변경한 부분은 이유와 영향 범위를 명시한다.
- 표준 클레임 검증은 타입 강제와 필수 여부 규칙을 분리해 문서화하고,
  기본값(예: 허용 오차, 현재 시간 계산 방식)을 명확히 기록한다.
- 테스트는 새로 추가한 동작과 TS 호환성 경계를 모두 포함하도록 작성한다.
  (성공/실패 케이스, 에러 타입 확인, 옵션 조합 검증)

## 다음 단계

- HMAC 외 알고리즘(RSA, ECDSA) 및 키 파싱(JWK/PEM) 구현을 확장한다.
- TypeScript 구현의 주요 모듈/기능을 매핑한 설계 문서를 보강한다.
- 테스트 벡터를 확보해 `tests/` 스캐폴딩을 확장한다.

## 간단한 사용 예시

```python
from jwt import encode, verify, ValidationOptions

token = encode({\"sub\": \"123\", \"exp\": 1710000000}, \"secret\", \"HS256\")
payload = verify(
    token,
    \"secret\",
    algorithms=[\"HS256\"],
    options=ValidationOptions(leeway=\"10 seconds\", issuer=\"https://issuer.example\"),
)
print(payload[\"sub\"])
```

## 테스트 실행

```bash
python -m unittest discover python/tests
```
