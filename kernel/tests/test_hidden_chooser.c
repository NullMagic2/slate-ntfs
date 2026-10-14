/*
 * Module: kernel.tests.hidden_chooser
 * Purpose: Verify ordinary hidden-file display in a real GTK 3 file chooser.
 * Created: 2026-10-14
 * Architecture: Inspects public tree models after asynchronous GIO loading;
 * the mounted driver supplies presentation hints and complete enumeration.
 */
#include <gtk/gtk.h>

static const gint64 load_timeout = 5 * G_USEC_PER_SEC;
static const gulong poll_microseconds = 10000;

typedef struct {
    GFile *folder;
    guint visible;
    guint git;
    guint system;
} Rows;

static void inspect_widget(GtkWidget *widget, gpointer context)
{
    Rows *rows = context;

    if (GTK_IS_TREE_VIEW(widget)) {
        GtkTreeModel *model = gtk_tree_view_get_model(GTK_TREE_VIEW(widget));

        if (model) {
            gint columns = gtk_tree_model_get_n_columns(model);

            for (gint column = 0; column < columns; column++) {
                GtkTreeIter iter;
                gboolean valid;

                if (!g_type_is_a(gtk_tree_model_get_column_type(model, column), G_TYPE_FILE))
                    continue;
                valid = gtk_tree_model_get_iter_first(model, &iter);
                while (valid) {
                    GFile *file = NULL;

                    gtk_tree_model_get(model, &iter, column, &file, -1);
                    if (file) {
                        GFile *parent = g_file_get_parent(file);

                        if (parent && g_file_equal(parent, rows->folder)) {
                            gchar *name = g_file_get_basename(file);

                            rows->visible += g_str_equal(name, "visible.txt");
                            rows->git += g_str_equal(name, ".git");
                            rows->system += g_str_equal(name, "system.dat");
                            g_free(name);
                        }
                        g_clear_object(&parent);
                        g_object_unref(file);
                    }
                    valid = gtk_tree_model_iter_next(model, &iter);
                }
            }
        }
    }
    if (GTK_IS_CONTAINER(widget))
        gtk_container_forall(GTK_CONTAINER(widget), inspect_widget, context);
}

static void check_rows(GtkWidget *dialog, GFile *folder, gboolean shown)
{
    gint64 deadline = g_get_monotonic_time() + load_timeout;
    Rows rows;

    do {
        while (g_main_context_iteration(NULL, FALSE)) {}
        rows = (Rows) { .folder = folder };
        inspect_widget(dialog, &rows);
        if (rows.visible == 1 && rows.git == (guint)shown && rows.system == (guint)shown)
            break;
        g_usleep(poll_microseconds);
    } while (g_get_monotonic_time() < deadline);
    g_assert_cmpuint(rows.visible, ==, 1);
    g_assert_cmpuint(rows.git, ==, shown);
    g_assert_cmpuint(rows.system, ==, shown);
}

int main(int argc, char **argv)
{
    GtkWidget *dialog;
    GFile *folder;

    gtk_init(&argc, &argv);
    g_assert_cmpint(argc, ==, 2);
    folder = g_file_new_for_path(argv[1]);
    dialog = gtk_file_chooser_dialog_new("Hidden file regression", NULL,
        GTK_FILE_CHOOSER_ACTION_OPEN, "Close", GTK_RESPONSE_CANCEL, NULL);
    gtk_file_chooser_set_show_hidden(GTK_FILE_CHOOSER(dialog), FALSE);
    g_assert_true(gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(dialog), argv[1]));
    check_rows(dialog, folder, FALSE);
    gtk_file_chooser_set_show_hidden(GTK_FILE_CHOOSER(dialog), TRUE);
    check_rows(dialog, folder, TRUE);
    gtk_file_chooser_set_show_hidden(GTK_FILE_CHOOSER(dialog), FALSE);
    check_rows(dialog, folder, FALSE);
    gtk_widget_destroy(dialog);
    g_object_unref(folder);
    g_print("GTK_HIDDEN_DISPLAY_PASS\n");
    return 0;
}
