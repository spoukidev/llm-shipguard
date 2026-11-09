PY ?= python

.PHONY: install test eval eval-holdout ablate demo demo-docker up down curl dashboard lint

install:
	$(PY) -m pip install -r requirements-dev.txt -r requirements-dashboard.txt

test:
	$(PY) -m pytest -q

eval:
	$(PY) -m eval.run_eval

eval-holdout:
	$(PY) -m eval.run_eval --attacks eval/corpus/holdout_attacks.jsonl --benign eval/corpus/holdout_benign.jsonl --tag holdout

ablate:
	$(PY) -m eval.run_eval --ablate --quiet && cat eval/results/report_dev.md

demo:              ## start mock + gateway in-process and run the before/after demo
	$(PY) -m demo.run_demo --start

up:
	docker compose up -d --build

down:
	docker compose down

demo-docker:       ## run the demo against the compose stack
	docker compose run --rm demo

curl:
	curl -s http://localhost:8088/v1/chat/completions -H 'Content-Type: application/json' \
	  -d '{"model":"mock-gullible-1","messages":[{"role":"user","content":"Hello! My email is sam@mail.example"}]}' | $(PY) -m json.tool

dashboard:
	streamlit run dashboard/app.py

lint:
	ruff check .
