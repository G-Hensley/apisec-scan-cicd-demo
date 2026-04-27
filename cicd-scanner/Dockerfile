FROM python:3.13.13

WORKDIR /apisec

RUN pip install --upgrade pip setuptools wheel \
 && pip install poetry pyyaml requests python-dotenv

COPY pyproject.toml poetry.lock ./
COPY __init__.py colors.py main.py models.py scanner.py table.py utils.py ./

RUN poetry config virtualenvs.create false \
 && poetry install --only main --no-root --no-interaction --no-ansi

RUN chmod +x ./main.py

CMD ["./main.py"]
