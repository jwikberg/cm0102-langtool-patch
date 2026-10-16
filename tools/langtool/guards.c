/* Fixed-address hooks for the hash-identified original executable only. */
typedef unsigned int u32;
typedef unsigned char u8;
#define OVERFLOW (*(volatile u32 *)GUARD_STATE)
#define WORD(object, offset) (*(u32 *)((u8 *)(object) + (offset)))

typedef struct {
    void *owner;
    u32 cursor;
    u32 start;
} EditState;

#define EDIT_STATES ((EditState *)(GUARD_STATE + 4))

typedef struct {
    const char *text;
    u32 length;
} Span;

static int fail(const char *message)
{
    ((void (__cdecl *)(const char *, int, const char *, int, int, int))0x4029b0)(
        "langtool expansion", 0, message, 1, 0, 0);
    ((void (__cdecl *)(const char *, const char *, int))0x410db0)(
        "Language database", message, 0);
    *(volatile u32 *)0x4bfa8c = 0;
    return 0;
}

static u32 length(const char *text, u32 capacity)
{
    u32 n = 0;
    while (n < capacity && text[n]) ++n;
    return n;
}

static int equal(Span a, Span b)
{
    u32 n;
    if (a.length != b.length) return 0;
    for (n = 0; n < a.length; ++n)
        if (a.text[n] != b.text[n]) return 0;
    return 1;
}

static int descriptors(const char *text, u32 size, Span *arguments, u32 *count,
                       u32 *compact)
{
    u32 i = 0;
    *count = *compact = 0;
    while (i < size) {
        u32 start;
        if (text[i] != '<') {
            if (text[i] == '>' || text[i] == '\b') return 0;
            ++*compact;
            ++i;
            continue;
        }
        if (*count == 10) return 0;
        start = i++;
        while (i < size && text[i] != '>') {
            if (text[i] == '<') return 0;
            ++i;
        }
        if (i == size) return 0;
        ++i;
        arguments[*count].text = text + start;
        arguments[(*count)++].length = i - start;
        ++*compact;
        /* The original parser consumes the byte following a descriptor. */
        if (i < size && text[i] == '<') return 0;
    }
    return 1;
}

static int source_arguments(const char *record, u32 size, Span *source, u32 *count)
{
    u32 compact, format = 0, n, m;
    if (size >= 2048)
        return fail("The source must contain at most 2047 bytes.");
    if (!descriptors(record, size, source, count, &compact))
        return fail("Invalid source argument markup (maximum 10 arguments; adjacent placeholders are unsupported).");
    for (n = 0; n < *count; ++n) {
        u32 i = 0;
        for (m = 0; m < n; ++m)
            if (equal(source[n], source[m]))
                return fail("Duplicate source argument descriptions.");
        while (i < source[n].length && source[n].text[i] != '%') ++i;
        if (i == source[n].length)
            return fail("A source argument has no printf conversion.");
        while (i < source[n].length && source[n].text[i] != ' ') {
            ++format;
            ++i;
        }
        ++format;
    }
    if (format >= 30)
        return fail("The printf argument-format field exceeds its 29-byte limit.");
    return 1;
}

int __cdecl guard_write(u32 *session, const char *record)
{
    Span source[10], translated[10];
    u32 size, count, compact, column, n, m;
    const char *text;
    if (OVERFLOW) {
        OVERFLOW = 0;
        return fail("A displayed field could not be decoded safely. No changes were written.");
    }
    if (!session || !record || session[1] < 1 || session[1] > 11)
        return fail("Invalid language database session.");
    size = length(record, 2048);
    if (!source_arguments(record, size, source, &count)) return 0;
    text = *(const char * const *)(record + 2048);
    if (session[1] > 1 && !text)
        return fail("Missing translation storage.");
    for (column = 1; column < session[1]; ++column, text += 32768) {
        u32 used;
        size = length(text, 32768);
        if (size == 32768)
            return fail("The annotated translation is too long.");
        if (!descriptors(text, size, translated, &used, &compact))
            return fail("Invalid translation argument markup (maximum 10 arguments; adjacent placeholders are unsupported).");
        if (compact > 2047)
            return fail("A decoded translation exceeds 2047 bytes. No changes were written.");
        for (n = 0; n < used; ++n) {
            for (m = 0; m < n; ++m)
                if (equal(translated[n], translated[m]))
                    return fail("Repeated argument descriptions are unsupported by this editor. No changes were written.");
            for (m = 0; m < count; ++m)
                if (equal(translated[n], source[m])) break;
            if (m == count)
                return fail("A translation references an unknown source argument. No changes were written.");
        }
    }
    return ((int (__cdecl *)(u32 *, const char *))GUARD_TRAMPOLINE)(session, record);
}

static int import_line(char *line, u32 size)
{
    Span arguments[10];
    u32 i = 0, output = 0, count, compact, start;
    int english;
    while (i < size && line[i] != ':') ++i;
    if (i == size || line[0] == '#') return 1;
    english = i == 6 && line[0] == 'E' && line[1] == 'N' && line[2] == 'G'
              && line[3] == '_' && line[4] == 'U' && line[5] == 'K';
    ++i;
    while (i < size) {
        u8 value = (u8)line[i++];
        if (value == '\\' && i < size) {
            value = (u8)line[i++];
            if (value == 'n') value = '\n';
            else if (value != '"') line[output++] = '\\';
            line[output++] = (char)value;
        } else if (value >= 32) {
            line[output++] = (char)value;
        }
    }
    line[output] = 0;
    while (output && line[output - 1] == ' ') line[--output] = 0;
    if (output > 4095)
        return fail("An imported annotated field exceeds its 4095-byte working limit.");
    start = 0;
    while (start < output && line[start] == ' ') ++start;
    if (english) return source_arguments(line + start, output - start, arguments, &count);
    if (!descriptors(line + start, output - start, arguments, &count, &compact)
            || compact > 2047)
        return fail("An imported translation has invalid markup or exceeds 2047 decoded bytes.");
    for (i = 0; i < count; ++i) {
        u32 j;
        for (j = 0; j < i; ++j)
            if (equal(arguments[i], arguments[j]))
                return fail("Repeated imported argument descriptions are unsupported.");
    }
    return 1;
}

int __cdecl guard_import(const char *input, const char *output, int version)
{
    void *file = ((void * (__cdecl *)(const char *, const char *))0x4427b5)(input, "rt");
    char *line;
    u32 used = 0;
    int valid = 1;
    if (!file) return fail("Unable to open the text file for import validation.");
    line = ((char * (__cdecl *)(u32))0x441d7e)(16384);
    if (!line) {
        ((int (__cdecl *)(void *))0x4426ce)(file);
        return fail("Unable to allocate the import validation buffer.");
    }
    for (;;) {
        int value = ((int (__cdecl *)(void *))0x44327f)(file);
        if (value < 0 && !used) break;
        if (value >= 0 && value != '\n') {
            if (used == 16383) {
                valid = fail("An imported line exceeds its encoded working limit.");
                break;
            }
            line[used++] = (char)value;
            continue;
        }
        line[used] = 0;
        valid = import_line(line, used);
        used = 0;
        if (!valid || value < 0) break;
    }
    ((int (__cdecl *)(void *))0x4426ce)(file);
    ((void (__cdecl *)(void *))0x441d73)(line);
    if (!valid) return 0;
    return ((int (__cdecl *)(const char *, const char *, int))GUARD_IMPORT_TRAMPOLINE)(
        input, output, version);
}

void __cdecl display_encode(char *destination, const char *source)
{
    u32 i, n = length(source, 32768), output = 0;
    if (n == 32768) {
        destination[0] = 0;
        OVERFLOW = 1;
        fail("The annotated field is not terminated within 32768 bytes.");
        return;
    }
    for (i = 0; i < n; ++i) {
        if (source[i] == '\n') {
            destination[output++] = '\\';
            destination[output++] = 'n';
        } else {
            destination[output++] = source[i];
        }
    }
    destination[output] = 0;
}

void __cdecl display_decode(char *destination, const char *source)
{
    u32 i, n = length(source, 65536), output = 0;
    u32 capacity = destination == *(char * volatile *)0x723e74 ? 2048 : 32768;
    if (n < 65536) {
        for (i = 0; i < n; ++i) {
            if (source[i] == '\\' && source[i + 1] == 'n') ++i;
            ++output;
        }
    }
    if (n == 65536 || output >= capacity) {
        OVERFLOW = 1;
        fail("The decoded field exceeds its memory limit. No changes were written.");
        return;
    }
    output = 0;
    for (i = 0; i < n; ++i) {
        if (source[i] == '\\' && source[i + 1] == 'n') {
            destination[output++] = '\n';
            ++i;
        } else {
            destination[output++] = source[i];
        }
    }
    destination[output] = 0;
}

void __attribute__((thiscall)) guard_widget_init(
    void *widget, u32 parent, u32 pool, u32 index, u32 flags,
    u32 left, u32 top, u32 right, u32 bottom, u32 extra, u32 order,
    u32 style, u32 color, u32 selected, u32 font, u32 height,
    u32 foreground, char *text, u32 limit, u32 tag, u32 callback, u32 table)
{
    char preview[256], *full = text;
    u32 n = text ? length(text, 65536) : 0, i;
    int expanded = (flags & 8) && limit == 65535 && tag == 0
                   && order >= 1 && order <= 10;
    if (expanded) {
        full = (char *)(UI_DATA_BASE + order * 65536);
        if (n == 65536) {
            fail("An editor field exceeds its display capacity.");
            return;
        }
        for (i = 0; i < n; ++i) full[i] = text[i];
        full[n] = 0;
        EDIT_STATES[order].owner = widget;
        EDIT_STATES[order].cursor = n;
        EDIT_STATES[order].start = 0;
    }
    if (n > 255) {
        for (i = 0; i < 255; ++i) preview[i] = full[i];
        preview[255] = 0;
        text = preview;
    } else {
        text = full;
    }
    ((__typeof__(&guard_widget_init))GUARD_WIDGET_TRAMPOLINE)(
        widget, parent, pool, index, flags, left, top, right, bottom,
        extra, order, style, color, selected, font, height, foreground,
        text, limit, tag, callback, table);
    if (flags & 8) WORD(widget, 0x54) = (u32)full;
}

static void edit_preview(void *widget, EditState *state, const char *text, u32 n)
{
    char *caption = (char *)widget + 0x80;
    u32 i, count, cursor = state->cursor, start = state->start;
    int active = (int)WORD(widget, 0x44) >= 0;
    int width = (int)WORD(widget, 0x18) - (int)WORD(widget, 0x10) - 10;
    int (__cdecl *measure)(u32, const char *) = (void *)0x40f5a0;
    if (start > cursor) start = cursor;
    if (cursor - start > 255) start = cursor - 255;
    for (;;) {
        count = cursor - start;
        for (i = 0; i < count; ++i) caption[i] = text[start + i];
        caption[count] = 0;
        if (!active || measure(*(unsigned short *)((u8 *)widget + 0x76), caption) <= width
            || start == cursor) break;
        ++start;
    }
    count = n - start;
    if (count > 255) count = 255;
    for (i = 0; i < count; ++i) caption[i] = text[start + i];
    caption[count] = 0;
    while (count && measure(*(unsigned short *)((u8 *)widget + 0x76), caption) > width)
        caption[--count] = 0;
    state->start = start;
    WORD(widget, 0x44) = active ? cursor - start : (u32)-1;
    if (WORD(widget, 0x4c))
        ((void (__cdecl *)(u32, u32, u32))0x40dbd0)(
            WORD(widget, 0x10), WORD(widget, 0x14), WORD(widget, 0x4c));
    ((void (__attribute__((thiscall)) *)(void *, int))0x4116e0)(widget, 0);
    ((void (__cdecl *)(u32, u32, u32, u32))0x40c920)(
        WORD(widget, 0x10), WORD(widget, 0x14),
        WORD(widget, 0x18), WORD(widget, 0x1c));
}

int __attribute__((thiscall)) guard_edit(void *root, u32 index)
{
    void *widget = (u8 *)root + 0xbb034 + (unsigned short)index * 396;
    char *text = (char *)WORD(widget, 0x54);
    u32 address = (u32)text, slot, n, cursor, key, character, i;
    int inside, active, redraw = 0;
    EditState *state;
    if (address < UI_DATA_BASE + 65536 || address >= UI_DATA_BASE + 11 * 65536
        || (address - UI_DATA_BASE) % 65536)
        return ((__typeof__(&guard_edit))GUARD_EDIT_TRAMPOLINE)(root, index);
    slot = (address - UI_DATA_BASE) / 65536;
    state = &EDIT_STATES[slot];
    if (state->owner != widget)
        return fail("The editor field has lost its persistent text storage.");
    n = length(text, 65536);
    if (n == 65536) return fail("An editor field is not terminated.");
    cursor = state->cursor;
    if (cursor > n) cursor = n;
    inside = ((int (__attribute__((thiscall)) *)(void *, u32, u32, u32, u32))0x405a80)(
        root, WORD(widget, 0x10), WORD(widget, 0x14),
        WORD(widget, 0x18), WORD(widget, 0x1c));
    active = (int)WORD(widget, 0x44) >= 0;
    if (*(volatile u32 *)0x4bfa8c) {
        if (inside && !active) {
            WORD(widget, 0x44) = 0;
            WORD(widget, 0x180) = 0;
            cursor = n;
            active = redraw = 1;
        } else if (!inside && active) {
            WORD(widget, 0x44) = (u32)-1;
            edit_preview(widget, state, text, n);
            return WORD(widget, 0x180) != 0;
        }
    }
    if (!active) return 0;
    key = *(volatile u32 *)0x4bfa60;
    character = *(volatile u32 *)0x4bfa7c;
    if (key == 9 || key == 13) {
        WORD(widget, 0x44) = (u32)-1;
        *(volatile u32 *)0x4bfa60 = *(volatile u32 *)0x4bfa7c = 0;
        edit_preview(widget, state, text, n);
        return WORD(widget, 0x180) != 0;
    }
    if (key == 0x24) cursor = 0;
    else if (key == 0x23) cursor = n;
    else if (key == 0x25 && cursor) --cursor;
    else if (key == 0x27 && cursor < n) ++cursor;
    else if ((key == 8 && cursor) || (key == 0x2e && cursor < n)) {
        if (key == 8) --cursor;
        for (i = cursor; i < n; ++i) text[i] = text[i + 1];
        --n;
        WORD(widget, 0x180) = 1;
    } else if (character >= 32 && character <= 255) {
        if (n == 65535) {
            *(volatile u32 *)0x4bfa60 = *(volatile u32 *)0x4bfa7c = 0;
            return fail("The editor field has reached its display limit.");
        }
        for (i = n + 1; i > cursor; --i) text[i] = text[i - 1];
        text[cursor++] = (char)character;
        ++n;
        WORD(widget, 0x180) = 1;
    }
    if (redraw || key || character) {
        state->cursor = cursor;
        edit_preview(widget, state, text, n);
        *(volatile u32 *)0x4bfa60 = *(volatile u32 *)0x4bfa7c = 0;
    }
    return 0;
}

void __attribute__((thiscall)) guard_settext(void *widget, const char *text, int redraw)
{
    char preview[256];
    u32 original = WORD(widget, 0x54), n, i;
    int expanded = original >= UI_DATA_BASE + 65536
                   && original < UI_DATA_BASE + 11 * 65536
                   && (original - UI_DATA_BASE) % 65536 == 0;
    if (!text) {
        ((__typeof__(&guard_settext))GUARD_SETTEXT_TRAMPOLINE)(widget, text, redraw);
        return;
    }
    n = length(text, 65536);
    if (n == 65536) {
        fail("A widget update exceeds its display capacity.");
        return;
    }
    if (!expanded && n > 255 && (WORD(widget, 0x0c) & 8)) {
        fail("This legacy input field cannot hold the supplied text.");
        return;
    }
    if (expanded) {
        char *full = (char *)original;
        for (i = 0; i <= n; ++i) full[i] = text[i];
        EDIT_STATES[(original - UI_DATA_BASE) / 65536].cursor = n;
        EDIT_STATES[(original - UI_DATA_BASE) / 65536].start = 0;
        WORD(widget, 0x54) = 0;
        WORD(widget, 0x44) = (u32)-1;
    }
    if (n > 255) {
        for (i = 0; i < 255; ++i) preview[i] = text[i];
        preview[255] = 0;
        text = preview;
    }
    ((__typeof__(&guard_settext))GUARD_SETTEXT_TRAMPOLINE)(widget, text, redraw);
    if (expanded) WORD(widget, 0x54) = original;
}

u32 __cdecl guard_fwrite(const u8 *source, u32 size, u32 count, void *file)
{
    u8 buffer[2048];
    u32 i;
    if (size != 1 || (count != 2048 && count != 30))
        return ((u32 (__cdecl *)(const u8 *, u32, u32, void *))0x442e5e)(
            source, size, count, file);
    i = 0;
    while (i < count && source[i]) {
        buffer[i] = source[i];
        ++i;
    }
    while (i < count) buffer[i++] = 0;
    return ((u32 (__cdecl *)(const u8 *, u32, u32, void *))0x442e5e)(
        buffer, size, count, file);
}
