coverage:
	coverage run -m unittest discover tests/
	coverage report -m

docs:
	pdoc -d=google -p=8088 eveauth
