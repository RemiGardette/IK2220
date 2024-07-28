poxdir ?= /opt/pox/
results_dir := ./results/
results_file := $(results_dir)phase_2_report.txt
controller_file := $(results_dir)phase_2_controller_logs.txt

topo:
	@echo "starting the topology! (i.e., running mininet)"
	cp -r ./applications/sdn/* $(poxdir)
	sudo python ./topology/topology.py

app:
	@echo "starting the baseController!"
	cp -r ./applications/sdn/* $(poxdir)ext/
	cp -r ./applications/nfv/* $(poxdir)ext/
	python $(poxdir)pox.py baseController

test:
	@echo "starting test scenarios!"
	touch $(results_dir)ids.report
  touch $(results_dir)lb1.report
  touch $(results_dir)napt.report
	make app > $(controller_file) &
	sudo python ./topology/topology_test.py > $(results_file)
	make clean

clean: 
	@echo "project files removed from pox directory!"
	rm -rf $(poxdir)sdn
	rm -rf $(poxdir)nfv
	sudo mn --link=tc --topo=mytopo
	kill $(shell sudo lsof -t -i:8080)

clean_results:
	@echo "results files removed!"
	rm -rf $(results_dir)*
