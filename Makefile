# Define the base name of your draft (without extension)
DRAFT_NAME := draft-xia-ipsecme-eesp-stateless-encryption

# Define source and target files
MD_SOURCE := $(DRAFT_NAME).md
XML_TARGET := draft/$(DRAFT_NAME).xml
TXT_TARGET := draft/$(DRAFT_NAME).txt
HTML_TARGET := draft/$(DRAFT_NAME).html
# If you have PDF support installed for xml2rfc:
# PDF_TARGET := $(DRAFT_NAME).pdf

# Define commands for the converters
# kramdown-rfc is typically available as a Ruby gem
# sudo gem install kramdown-rfc
KRAMDOWN_RFC := kramdown-rfc

# xml2rfc is a Python package
# pip install xml2rfc
# For PDF support: pip install "xml2rfc[pdf]"
XML2RFC := xml2rfc

# Default target: build all common formats
all: $(TXT_TARGET) $(HTML_TARGET) # $(PDF_TARGET)

# Rule to convert Markdown to RFCXML
$(XML_TARGET): $(MD_SOURCE)
	mkdir -p draft || true
	@echo "Converting $(MD_SOURCE) to RFCXML ($(XML_TARGET))..."
	$(KRAMDOWN_RFC) $< > $@
	@echo "RFCXML conversion complete $@"

# Rule to convert RFCXML to TXT
$(TXT_TARGET): $(XML_TARGET)
	@echo "Converting $(XML_TARGET) to TXT ($(TXT_TARGET))..."
	$(XML2RFC) --text $< -o $@
	@echo "TXT conversion complete."

# Rule to convert RFCXML to HTML
$(HTML_TARGET): $(XML_TARGET)
	@echo "Converting $(XML_TARGET) to HTML ($(HTML_TARGET))..."
	$(XML2RFC) --html $< -o $@
	@echo "HTML conversion complete."

# Rule to convert RFCXML to PDF (uncomment if you have PDF setup)
# $(PDF_TARGET): $(XML_TARGET)
# 	@echo "Converting $(XML_TARGET) to PDF ($(PDF_TARGET))..."
# 	$(XML2RFC) --pdf $< -o $@
# 	@echo "PDF conversion complete."

# Clean up generated files
clean:
	@echo "Cleaning up generated files..."
	rm -f $(XML_TARGET) $(TXT_TARGET) $(HTML_TARGET) $(PDF_TARGET)
	@echo "Clean up complete."

.PHONY: all clean
