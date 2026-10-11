# Лабораторна робота №2

## Варіант 9: аудитор безпеки HTTP-заголовків

Реалізація використовує тільки стандартну бібліотеку Python. Вхідний файл містить JSON-масив ресурсів із полями `url` та `headers`. Також приймається об'єкт із ключем `resources` або `targets`.

## Структура

```text
labs/lab02/
├── __init__.py
├── main.py                  # команди demo та analyze
├── task1.py                 # User, Admin, Session, AuditLog, UserAccount
├── task2.py                 # аналізатор HTTP-заголовків, варіант 9
└── data/
    └── http_headers.json    # навчальні вхідні дані
```

## Запуск

Команди виконуються з кореня репозиторію через Python launcher Windows:

```powershell
py -m labs.lab02.main demo
py -m labs.lab02.main analyze `
  --headers-file labs/lab02/data/http_headers.json `
  --output-csv labs/lab02/data/headers_audit.csv `
  --strict
```

Прямий запуск аналізатора також доступний:

```powershell
py -m labs.lab02.task2 --headers-file labs/lab02/data/http_headers.json --output-csv labs/lab02/data/headers_audit.csv
```

## Параметри analyze

- `--headers-file` - обов'язковий шлях до JSON-файлу.
- `--output-csv` - обов'язковий шлях до CSV-звіту; батьківський каталог створюється автоматично.
- `--strict` - переводить ресурс у `FAIL`, якщо виявлена будь-яка проблема.
- `--log-level` - `DEBUG`, `INFO`, `WARNING` або `ERROR`; за замовчуванням `INFO`.

Для кожного ресурсу перевіряються `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options` і `X-Content-Type-Options`. Відсутній заголовок зменшує оцінку на 20 балів. Версія програмного забезпечення в `Server` або `X-Powered-By`, знайдена регулярним виразом, зменшує оцінку на 5 балів і фіксується як витік.

## Обробка помилок

Помилки читання файлу, JSON, структури вхідних даних і запису звіту логуються як `ERROR`; команда завершується з кодом `1`. Некоректні CLI-параметри обробляє `argparse`. Паролі в `task1.py` не зберігаються у відкритому вигляді: використовується `pbkdf2_hmac` із випадковою сіллю та `hmac.compare_digest`.

## Результат на навчальних даних

- `secure.example.com`: 100/100, `PASS`.
- `legacy.example.com`: відсутні три security headers і виявлено `Apache/2.4.41`, тому ресурс має високий ризик.
- `portal.example.com`: відсутній `X-Frame-Options` і виявлено `PHP/7.4.3`; у строгому режимі статус `FAIL`.

## Перевірка якості

```powershell
py -m compileall -q shared labs
ruff check .
ruff format --check .
```
