coverage:
	coverage run -m unittest discover tests/
	coverage report -m

docs:
	pdoc -d=google eveauth
