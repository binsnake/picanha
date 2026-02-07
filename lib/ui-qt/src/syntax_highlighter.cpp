#include <picanha/ui-qt/syntax_highlighter.hpp>

namespace picanha::ui {

// LLVM IR Highlighter

IRHighlighter::IRHighlighter(QTextDocument* parent)
    : QSyntaxHighlighter(parent)
{
    // Keywords
    QTextCharFormat keyword_format;
    keyword_format.setForeground(QColor(0x56, 0x9c, 0xd6));
    keyword_format.setFontWeight(QFont::Bold);

    QStringList keywords = {
        "define", "declare", "global", "constant", "internal", "external",
        "private", "linkonce", "linkonce_odr", "weak", "weak_odr", "common",
        "appending", "extern_weak", "available_externally", "default", "hidden",
        "protected", "unnamed_addr", "local_unnamed_addr", "to", "ret", "br",
        "switch", "indirectbr", "invoke", "resume", "unreachable", "add", "fadd",
        "sub", "fsub", "mul", "fmul", "udiv", "sdiv", "fdiv", "urem", "srem",
        "frem", "shl", "lshr", "ashr", "and", "or", "xor", "extractelement",
        "insertelement", "shufflevector", "extractvalue", "insertvalue", "alloca",
        "load", "store", "fence", "cmpxchg", "atomicrmw", "getelementptr", "trunc",
        "zext", "sext", "fptrunc", "fpext", "fptoui", "fptosi", "uitofp", "sitofp",
        "ptrtoint", "inttoptr", "bitcast", "addrspacecast", "icmp", "fcmp", "phi",
        "select", "call", "tail", "va_arg", "landingpad", "catchpad", "cleanuppad",
        "catchret", "cleanupret", "catchswitch", "nuw", "nsw", "exact", "inbounds",
        "volatile", "atomic", "unordered", "monotonic", "acquire", "release",
        "acq_rel", "seq_cst", "singlethread", "eq", "ne", "ugt", "uge", "ult",
        "ule", "sgt", "sge", "slt", "sle", "oeq", "ogt", "oge", "olt", "ole",
        "one", "ord", "ueq", "une", "uno", "nnan", "ninf", "nsz", "arcp",
        "contract", "afn", "reassoc", "fast", "noalias", "nocapture", "nonnull",
        "null", "undef", "true", "false", "zeroinitializer", "poison"
    };

    for (const QString& keyword : keywords) {
        HighlightRule rule;
        rule.pattern = QRegularExpression("\\b" + keyword + "\\b");
        rule.format = keyword_format;
        rules_.push_back(rule);
    }

    // Types
    QTextCharFormat type_format;
    type_format.setForeground(QColor(0x4e, 0xc9, 0xb0));

    QStringList types = {
        "void", "half", "float", "double", "x86_fp80", "fp128", "ppc_fp128",
        "label", "metadata", "token"
    };

    for (const QString& type : types) {
        HighlightRule rule;
        rule.pattern = QRegularExpression("\\b" + type + "\\b");
        rule.format = type_format;
        rules_.push_back(rule);
    }

    // Integer types (i1, i8, i16, i32, i64, i128, etc.)
    {
        HighlightRule rule;
        rule.pattern = QRegularExpression("\\bi\\d+\\b");
        rule.format = type_format;
        rules_.push_back(rule);
    }

    // Pointers (ptr)
    {
        HighlightRule rule;
        rule.pattern = QRegularExpression("\\bptr\\b");
        rule.format = type_format;
        rules_.push_back(rule);
    }

    // Labels (%name:)
    QTextCharFormat label_format;
    label_format.setForeground(QColor(0xdc, 0xdc, 0xaa));
    {
        HighlightRule rule;
        rule.pattern = QRegularExpression("^\\s*[\\w.]+:");
        rule.format = label_format;
        rules_.push_back(rule);
    }

    // Local variables (%name)
    QTextCharFormat local_format;
    local_format.setForeground(QColor(0x9c, 0xdc, 0xfe));
    {
        HighlightRule rule;
        rule.pattern = QRegularExpression("%[\\w.]+");
        rule.format = local_format;
        rules_.push_back(rule);
    }

    // Global variables (@name)
    QTextCharFormat global_format;
    global_format.setForeground(QColor(0xdc, 0xdc, 0xaa));
    {
        HighlightRule rule;
        rule.pattern = QRegularExpression("@[\\w.]+");
        rule.format = global_format;
        rules_.push_back(rule);
    }

    // Numbers
    QTextCharFormat number_format;
    number_format.setForeground(QColor(0xb5, 0xce, 0xa8));
    {
        HighlightRule rule;
        rule.pattern = QRegularExpression("\\b-?\\d+(\\.\\d+)?([eE][+-]?\\d+)?\\b");
        rule.format = number_format;
        rules_.push_back(rule);
    }

    // Hex numbers
    {
        HighlightRule rule;
        rule.pattern = QRegularExpression("\\b0x[0-9a-fA-F]+\\b");
        rule.format = number_format;
        rules_.push_back(rule);
    }

    // Comments
    QTextCharFormat comment_format;
    comment_format.setForeground(QColor(0x6a, 0x99, 0x55));
    {
        HighlightRule rule;
        rule.pattern = QRegularExpression(";.*$");
        rule.format = comment_format;
        rules_.push_back(rule);
    }

    // Strings
    QTextCharFormat string_format;
    string_format.setForeground(QColor(0xce, 0x91, 0x78));
    {
        HighlightRule rule;
        rule.pattern = QRegularExpression("\"[^\"]*\"");
        rule.format = string_format;
        rules_.push_back(rule);
    }

    // Metadata
    QTextCharFormat metadata_format;
    metadata_format.setForeground(QColor(0x80, 0x80, 0x80));
    {
        HighlightRule rule;
        rule.pattern = QRegularExpression("![\\w.]+");
        rule.format = metadata_format;
        rules_.push_back(rule);
    }
}

void IRHighlighter::highlightBlock(const QString& text) {
    for (const auto& rule : rules_) {
        QRegularExpressionMatchIterator it = rule.pattern.globalMatch(text);
        while (it.hasNext()) {
            QRegularExpressionMatch match = it.next();
            setFormat(match.capturedStart(), match.capturedLength(), rule.format);
        }
    }
}

// C Highlighter

CHighlighter::CHighlighter(QTextDocument* parent)
    : QSyntaxHighlighter(parent)
{
    // Keywords
    QTextCharFormat keyword_format;
    keyword_format.setForeground(QColor(0x56, 0x9c, 0xd6));
    keyword_format.setFontWeight(QFont::Bold);

    QStringList keywords = {
        "auto", "break", "case", "char", "const", "continue", "default", "do",
        "double", "else", "enum", "extern", "float", "for", "goto", "if", "inline",
        "int", "long", "register", "restrict", "return", "short", "signed", "sizeof",
        "static", "struct", "switch", "typedef", "union", "unsigned", "void",
        "volatile", "while", "_Bool", "_Complex", "_Imaginary", "bool", "true",
        "false", "NULL", "nullptr"
    };

    for (const QString& keyword : keywords) {
        HighlightRule rule;
        rule.pattern = QRegularExpression("\\b" + keyword + "\\b");
        rule.format = keyword_format;
        rules_.push_back(rule);
    }

    // Types (common typedefs)
    QTextCharFormat type_format;
    type_format.setForeground(QColor(0x4e, 0xc9, 0xb0));

    QStringList types = {
        "int8_t", "int16_t", "int32_t", "int64_t",
        "uint8_t", "uint16_t", "uint32_t", "uint64_t",
        "size_t", "ssize_t", "ptrdiff_t", "intptr_t", "uintptr_t",
        "BYTE", "WORD", "DWORD", "QWORD", "BOOL", "HANDLE",
        "PVOID", "LPVOID", "LPCSTR", "LPSTR", "LPCWSTR", "LPWSTR"
    };

    for (const QString& type : types) {
        HighlightRule rule;
        rule.pattern = QRegularExpression("\\b" + type + "\\b");
        rule.format = type_format;
        rules_.push_back(rule);
    }

    // Function calls
    QTextCharFormat function_format;
    function_format.setForeground(QColor(0xdc, 0xdc, 0xaa));
    {
        HighlightRule rule;
        rule.pattern = QRegularExpression("\\b[a-zA-Z_][a-zA-Z0-9_]*\\s*(?=\\()");
        rule.format = function_format;
        rules_.push_back(rule);
    }

    // Numbers
    QTextCharFormat number_format;
    number_format.setForeground(QColor(0xb5, 0xce, 0xa8));
    {
        HighlightRule rule;
        rule.pattern = QRegularExpression("\\b-?\\d+(\\.\\d+)?([eE][+-]?\\d+)?[fFlLuU]*\\b");
        rule.format = number_format;
        rules_.push_back(rule);
    }

    // Hex numbers
    {
        HighlightRule rule;
        rule.pattern = QRegularExpression("\\b0[xX][0-9a-fA-F]+[uUlL]*\\b");
        rule.format = number_format;
        rules_.push_back(rule);
    }

    // Strings
    QTextCharFormat string_format;
    string_format.setForeground(QColor(0xce, 0x91, 0x78));
    {
        HighlightRule rule;
        rule.pattern = QRegularExpression("\"(?:[^\"\\\\]|\\\\.)*\"");
        rule.format = string_format;
        rules_.push_back(rule);
    }

    // Characters
    {
        HighlightRule rule;
        rule.pattern = QRegularExpression("'(?:[^'\\\\]|\\\\.)*'");
        rule.format = string_format;
        rules_.push_back(rule);
    }

    // Single-line comments
    comment_format_.setForeground(QColor(0x6a, 0x99, 0x55));
    {
        HighlightRule rule;
        rule.pattern = QRegularExpression("//.*$");
        rule.format = comment_format_;
        rules_.push_back(rule);
    }

    // Preprocessor directives
    QTextCharFormat preproc_format;
    preproc_format.setForeground(QColor(0xc5, 0x86, 0xc0));
    {
        HighlightRule rule;
        rule.pattern = QRegularExpression("^\\s*#.*$");
        rule.format = preproc_format;
        rules_.push_back(rule);
    }

    // Multi-line comments
    comment_start_ = QRegularExpression("/\\*");
    comment_end_ = QRegularExpression("\\*/");
}

void CHighlighter::highlightBlock(const QString& text) {
    // Apply single-line rules
    for (const auto& rule : rules_) {
        QRegularExpressionMatchIterator it = rule.pattern.globalMatch(text);
        while (it.hasNext()) {
            QRegularExpressionMatch match = it.next();
            setFormat(match.capturedStart(), match.capturedLength(), rule.format);
        }
    }

    // Handle multi-line comments
    setCurrentBlockState(0);

    int startIndex = 0;
    if (previousBlockState() != 1) {
        startIndex = text.indexOf(comment_start_);
    }

    while (startIndex >= 0) {
        QRegularExpressionMatch endMatch;
        int endIndex = text.indexOf(comment_end_, startIndex, &endMatch);
        int commentLength;

        if (endIndex == -1) {
            setCurrentBlockState(1);
            commentLength = text.length() - startIndex;
        } else {
            commentLength = endIndex - startIndex + endMatch.capturedLength();
        }

        setFormat(startIndex, commentLength, comment_format_);
        startIndex = text.indexOf(comment_start_, startIndex + commentLength);
    }
}

} // namespace picanha::ui
