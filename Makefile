LOG ?= data/raw/OpenSSH_full.log
YEAR ?= 2015

install:
	pip install -r requirements.txt

test:
	python -m pytest -q

run:            ## analyse a real log:  make run LOG=data/raw/OpenSSH_full.log
	python -m sla run --log $(LOG) --year $(YEAR)
	python scripts/update_readme_results.py

sample:         ## analyse the bundled 2,000-line Loghub sample
	python -m sla run --log data/raw/OpenSSH_2k.log --out reports/sample_run_loghub_2k

demo:           ## SYNTHETIC 30-day log, to see forecasting and the dashboard populated
	python -m sla demo
	SLA_DB=data/processed/demo.db streamlit run app/dashboard.py

dashboard:
	streamlit run app/dashboard.py
