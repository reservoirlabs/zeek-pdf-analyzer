module PDF;

export {
    redef enum Log::ID +=  { LOG };

    ## This record reflects the pdf info we are logging
    type LogInfo: record {
        ts: time &log;                      # Timestamp
        version: string &log;               # PDF version
        pages: count &log;                  # Number of pages
        files: bool &log;                   # Contains files?
        javascript: bool &log;              # Contains embedded javascript?
        encrypted: bool &log;               # Password protected?
        linearized: bool &log;              # Supports web optimization?
        printing: bool &log;                # Allow printing?
        editing: bool &log;                 # Allow editing?
        copying: bool &log;                 # Allow copying?
        note_editing: bool &log;            # Allow note editing?
        accessibility: bool &log;           # Accessible?
        doc_assembly: bool &log;            # Doc assembly enabled? 
        body: string &log &optional;        # PDF body text
        urls: string &log &optional;        # Embedded urls
        embfiles: string &log &optional;    # Embedded files
        fid: string &log;                   # File ID
    };
}

event zeek_init() {
    Files::register_for_mime_type(Files::ANALYZER_PDF, "application/pdf");
    Log::create_stream(PDF::LOG, [$columns=LogInfo, $path="pdf"]);
}

event pdf_info(f: fa_file, info: PDF::Info) {

    # Simply logging each PDF record field
    local rec: PDF::LogInfo = [$ts=network_time(),
                                $version=info$version,
                                $pages=info$pages,
                                $files=info$files,
                                $javascript=info$javascript,
                                $encrypted=info$encrypted,
                                $linearized=info$linearized,
                                $printing=info$allowed$printing,
                                $editing=info$allowed$editing,
                                $copying=info$allowed$copying,
                                $note_editing=info$allowed$note_editing,
                                $accessibility=info$allowed$accessibility,
                                $doc_assembly=info$allowed$doc_assembly,
                                $body=(info?$body ? info$body : ""),
                                $urls=(info?$urls ? info$urls : ""),
                                $embfiles=(info?$embfiles ? info$embfiles : ""),
                                $fid=f$id];

    Log::write(PDF::LOG, rec);
}

