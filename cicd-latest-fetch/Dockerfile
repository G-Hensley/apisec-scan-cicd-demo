FROM python:3.13.13

WORKDIR /apisec

RUN pip install --upgrade pip setuptools wheel \
 && pip install requests python-dotenv

COPY __init__.py colors.py main.py models.py scanner.py table.py utils.py ./

RUN chmod +x ./main.py

CMD ["./main.py"]
