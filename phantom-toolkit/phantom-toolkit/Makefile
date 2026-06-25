# PHANTOM Security Toolkit — Master Makefile
# Builds all 8 tools from one command: make all

TOOLS = ids sniffer httpd port-scanner dns-resolver bof-study arp-monitor pe-elf-analyzer

.PHONY: all clean $(TOOLS)

all: $(TOOLS)
	@echo ""
	@echo "\033[1;32m╔══════════════════════════════════════════════╗"
	@echo "║   PHANTOM Toolkit build complete!           ║"
	@echo "╚══════════════════════════════════════════════╝\033[0m"
	@echo ""
	@echo "  phantom-ids       → ids/phantom-ids"
	@echo "  phantom-sniffer   → sniffer/phantom-sniffer"
	@echo "  phantom-httpd     → httpd/phantom-httpd"
	@echo "  phantom-scan      → port-scanner/phantom-scan"
	@echo "  phantom-dns       → dns-resolver/phantom-dns"
	@echo "  bof study         → bof-study/{vuln,defended,exploit_demo}"
	@echo "  phantom-arp       → arp-monitor/phantom-arp"
	@echo "  phantom-analyzer  → pe-elf-analyzer/phantom-analyzer"

ids:
	$(MAKE) -C ids

sniffer:
	$(MAKE) -C sniffer

httpd:
	$(MAKE) -C httpd

port-scanner:
	$(MAKE) -C port-scanner

dns-resolver:
	$(MAKE) -C dns-resolver

bof-study:
	$(MAKE) -C bof-study

arp-monitor:
	$(MAKE) -C arp-monitor

pe-elf-analyzer:
	$(MAKE) -C pe-elf-analyzer

clean:
	@for t in $(TOOLS); do $(MAKE) -C $$t clean; done
	@echo "All clean."
