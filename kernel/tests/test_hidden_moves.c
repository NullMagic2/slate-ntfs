/*
 * Module: kernel.tests.hidden_moves
 * Purpose: Verify GIO display hints and recursive moves on disposable mounts.
 * Created: 2026-10-14
 * Architecture: Reads the mounted VFS through the desktop's GIO API; display
 * filtering never determines which children its copy/delete backend processes.
 */
#include <gio/gio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <errno.h>

static const char query_attributes[] = G_FILE_ATTRIBUTE_STANDARD_NAME ","
    G_FILE_ATTRIBUTE_STANDARD_TYPE "," G_FILE_ATTRIBUTE_STANDARD_IS_HIDDEN;
static const char history[] = "preserved repository history\n";
static const char system_data[] = "preserved ordinary system file\n";

static void require_success(gboolean success, GError **error)
{
    if (!success)
        g_error("GIO operation failed: %s", *error ? (*error)->message : "no error detail");
    g_clear_error(error);
}

static void copy_tree(GFile *source, GFile *target)
{
    GError *error = NULL;
    GFileInfo *info = g_file_query_info(source, query_attributes,
        G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS, NULL, &error);

    require_success(info != NULL, &error);
    if (g_file_info_get_file_type(info) == G_FILE_TYPE_DIRECTORY) {
        GFileEnumerator *children;
        GFileInfo *child;

        require_success(g_file_make_directory(target, NULL, &error), &error);
        children = g_file_enumerate_children(source, query_attributes,
            G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS, NULL, &error);
        require_success(children != NULL, &error);
        while ((child = g_file_enumerator_next_file(children, NULL, &error))) {
            GFile *from = g_file_get_child(source, g_file_info_get_name(child));
            GFile *to = g_file_get_child(target, g_file_info_get_name(child));

            copy_tree(from, to);
            g_object_unref(from);
            g_object_unref(to);
            g_object_unref(child);
        }
        require_success(error == NULL, &error);
        g_object_unref(children);
    } else {
        require_success(g_file_copy(source, target, G_FILE_COPY_NOFOLLOW_SYMLINKS,
            NULL, NULL, NULL, &error), &error);
    }
    g_object_unref(info);
    require_success(g_file_delete(source, NULL, &error), &error);
}

static void check_contents(GFile *parent, const char *name, const char *expected)
{
    GFile *file = g_file_get_child(parent, name);
    GError *error = NULL;
    gchar *contents = NULL;
    gsize length;

    require_success(g_file_load_contents(file, NULL, &contents, &length, NULL, &error), &error);
    g_assert_cmpuint(length, ==, strlen(expected));
    g_assert_cmpstr(contents, ==, expected);
    g_free(contents);
    g_object_unref(file);
}

static void check_listing(GFile *parent, gboolean system_hidden)
{
    GError *error = NULL;
    GFileEnumerator *children = g_file_enumerate_children(parent, query_attributes,
        G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS, NULL, &error);
    GFileInfo *child;
    gboolean found_git = FALSE;
    gboolean found_system = FALSE;

    require_success(children != NULL, &error);
    while ((child = g_file_enumerator_next_file(children, NULL, &error))) {
        const gchar *name = g_file_info_get_name(child);

        if (g_str_equal(name, ".git")) {
            found_git = TRUE;
            g_assert_true(g_file_info_get_is_hidden(child));
        } else if (g_str_equal(name, "system.dat")) {
            found_system = TRUE;
            g_assert_cmpint(g_file_info_get_is_hidden(child), ==, system_hidden);
        }
        g_assert_cmpstr(name, !=, ".hidden");
        g_object_unref(child);
    }
    require_success(error == NULL, &error);
    g_assert_true(found_git);
    g_assert_true(found_system);
    g_object_unref(children);
}

static void check_large_hints(GFile *parent)
{
    GFile *hint = g_file_get_child(parent, ".hidden");
    GError *error = NULL;
    gchar *contents = NULL;
    gchar **lines;
    GHashTable *names = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    GFileEnumerator *children;
    GFileInfo *child;
    guint count = 0;
    guint expected_count;

    require_success(g_file_load_contents(hint, NULL, &contents, NULL, NULL, &error), &error);
    lines = g_strsplit(contents, "\n", -1);
    for (gchar **line = lines; *line; line++) {
        if (**line)
            g_assert_true(g_hash_table_add(names, g_strdup(*line)));
    }
    expected_count = g_hash_table_size(names);
    g_assert_cmpuint(strlen(contents), >, sysconf(_SC_PAGESIZE));
    children = g_file_enumerate_children(parent, query_attributes,
        G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS, NULL, &error);
    require_success(children != NULL, &error);
    while ((child = g_file_enumerator_next_file(children, NULL, &error))) {
        g_assert_true(g_file_info_get_is_hidden(child));
        g_assert_true(g_hash_table_remove(names, g_file_info_get_name(child)));
        count++;
        g_object_unref(child);
    }
    require_success(error == NULL, &error);
    g_assert_cmpuint(count, ==, expected_count);
    g_assert_cmpuint(g_hash_table_size(names), ==, 0);
    g_object_unref(children);
    g_hash_table_unref(names);
    g_strfreev(lines);
    g_free(contents);
    g_object_unref(hint);
}

int main(int argc, char **argv)
{
    GFile *source;

    if (argc < 3)
        g_error("usage: test-hidden-moves check|shown|large|move|remount SOURCE [TARGET]");
    if (g_str_equal(argv[1], "remount")) {
        g_assert_cmpint(argc, ==, 4);
        if (mount(NULL, argv[2], NULL, MS_REMOUNT, argv[3]) != 0)
            g_error("private remount failed: %s", g_strerror(errno));
        return 0;
    }
    source = g_file_new_for_path(argv[2]);
    if (g_str_equal(argv[1], "large")) {
        check_large_hints(source);
        g_object_unref(source);
        g_print("GIO_LARGE_HIDDEN_HINTS_PASS\n");
        return 0;
    }
    check_contents(source, ".git/config", history);
    check_contents(source, ".git/objects/df/readonly-object", history);
    check_contents(source, "system.dat", system_data);
    check_listing(source, !g_str_equal(argv[1], "shown"));
    if (g_str_equal(argv[1], "move")) {
        GFile *target;

        g_assert_cmpint(argc, ==, 4);
        GFile *object = g_file_get_child(source, ".git/objects/df/readonly-object");
        GError *error = NULL;
        GFileInfo *permissions = g_file_query_info(object,
            G_FILE_ATTRIBUTE_ACCESS_CAN_DELETE "," G_FILE_ATTRIBUTE_ACCESS_CAN_WRITE,
            G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS, NULL, &error);

        require_success(permissions != NULL, &error);
        g_assert_true(g_file_info_get_attribute_boolean(permissions, G_FILE_ATTRIBUTE_ACCESS_CAN_DELETE));
        g_assert_false(g_file_info_get_attribute_boolean(permissions, G_FILE_ATTRIBUTE_ACCESS_CAN_WRITE));
        g_object_unref(permissions);
        g_object_unref(object);
        target = g_file_new_for_path(argv[3]);
        copy_tree(source, target);
        check_contents(target, ".git/config", history);
        check_contents(target, ".git/objects/df/readonly-object", history);
        check_contents(target, "system.dat", system_data);
        g_assert_false(g_file_query_exists(source, NULL));
        g_object_unref(target);
    } else {
        g_assert_true(g_str_equal(argv[1], "check") || g_str_equal(argv[1], "shown"));
    }
    g_object_unref(source);
    g_print("GIO_HIDDEN_MOVE_PASS:%s\n", argv[1]);
    return 0;
}
