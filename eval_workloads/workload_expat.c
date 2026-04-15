/*
    libexpat: CVE-2022-25236 / CVE-2022-40674 / CVE-2022-25315

    Target symbols: XML_Parse, XML_ParserCreate, XML_SetElementHandler, etc.
    
    These are standard XML parsing API functions. We parse a small
    well-formed XML document.
*/

#include <stdio.h>
#include <string.h>
#include <expat.h>

static void start_element(void *data, const XML_Char *name, const XML_Char **attrs) {
    printf("[expat]   Start element: %s\n", name);
    (void)data;
    (void)attrs;
}

static void end_element(void *data, const XML_Char *name) {
    printf("[expat]   End element: %s\n", name);
    (void)data;
}

int main(void) {
    /* XML_ParserCreate — target symbol */
    XML_Parser parser = XML_ParserCreate(NULL);
    if (!parser) {
        fprintf(stderr, "XML_ParserCreate() failed\n");
        return 1;
    }
    printf("[expat] XML_ParserCreate() called\n");

    /* XML_SetElementHandler — may also be a target symbol */
    XML_SetElementHandler(parser, start_element, end_element);
    printf("[expat] XML_SetElementHandler() called\n");

    /* XML_Parse — target symbol */
    const char *xml = "<root><item id=\"1\">hello</item><item id=\"2\">world</item></root>";
    int len = (int)strlen(xml);
    enum XML_Status status = XML_Parse(parser, xml, len, 1);
    if (status == XML_STATUS_ERROR) {
        fprintf(stderr, "XML_Parse() error: %s\n",
                XML_ErrorString(XML_GetErrorCode(parser)));
        XML_ParserFree(parser);
        return 1;
    }
    printf("[expat] XML_Parse() called successfully — parsed %d bytes\n", len);

    XML_ParserFree(parser);
    printf("[expat] Workload complete.\n");
    return 0;
}
