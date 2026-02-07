#pragma once

#include <QSyntaxHighlighter>
#include <QTextCharFormat>
#include <QRegularExpression>

#include <vector>

namespace picanha::ui {

// LLVM IR syntax highlighter
class IRHighlighter : public QSyntaxHighlighter {
    Q_OBJECT

public:
    explicit IRHighlighter(QTextDocument* parent = nullptr);

protected:
    void highlightBlock(const QString& text) override;

private:
    struct HighlightRule {
        QRegularExpression pattern;
        QTextCharFormat format;
    };

    std::vector<HighlightRule> rules_;
};

// C syntax highlighter (for decompiled code)
class CHighlighter : public QSyntaxHighlighter {
    Q_OBJECT

public:
    explicit CHighlighter(QTextDocument* parent = nullptr);

protected:
    void highlightBlock(const QString& text) override;

private:
    struct HighlightRule {
        QRegularExpression pattern;
        QTextCharFormat format;
    };

    std::vector<HighlightRule> rules_;
    QRegularExpression comment_start_;
    QRegularExpression comment_end_;
    QTextCharFormat comment_format_;
};

} // namespace picanha::ui
