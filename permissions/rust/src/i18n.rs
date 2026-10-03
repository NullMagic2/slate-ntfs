//! Module: ntfs_permissions::i18n
//! Purpose: Translate interface text into Portuguese, Spanish, English and Greek.
//! Created: 2026-10-01
//! Architecture: Frontend and backend messages share English keys and placeholder checks.
//! Missing translations fall back to English. Per-user preferences override
//! the initial desktop language; filesystem policy remains in core.

use std::cell::Cell;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Language {
    Pt,
    Es,
    En,
    El,
}

impl Language {
    /// Menu order, with each language's own name and flag file.
    pub const ALL: [Language; 4] = [Language::Pt, Language::Es, Language::En, Language::El];
    pub fn code(self) -> &'static str {
        match self {
            Language::Pt => "pt",
            Language::Es => "es",
            Language::En => "en",
            Language::El => "el",
        }
    }
    pub fn native_name(self) -> &'static str {
        match self {
            Language::Pt => "Português (Brasil)",
            Language::Es => "Español",
            Language::En => "English",
            Language::El => "Ελληνικά",
        }
    }
    pub fn flag(self) -> &'static str {
        match self {
            Language::Pt => "br",
            Language::Es => "es",
            Language::En => "us",
            Language::El => "gr",
        }
    }
    pub fn from_code(code: &str) -> Option<Self> {
        Language::ALL.into_iter().find(|l| l.code() == code)
    }
    fn catalog(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Language::Pt => PT,
            Language::Es => ES,
            Language::El => EL,
            Language::En => &[],
        }
    }
}

thread_local! {
    static CURRENT: Cell<Language> = const { Cell::new(Language::En) };
}

fn config_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config"));
    base.join("slate-ntfs").join("language")
}

/// The desktop's language if supported, else English.
pub fn system_language() -> Language {
    for variable in ["LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"] {
        let value = std::env::var(variable).unwrap_or_default();
        for part in value.split(':') {
            let code = part.split(['_', '.', '@']).next().unwrap_or("").to_lowercase();
            if let Some(language) = Language::from_code(&code) {
                return language;
            }
        }
    }
    Language::En
}

/// Load the remembered choice (or the desktop's language).
pub fn load() -> Language {
    let saved = std::fs::read_to_string(config_path()).ok().and_then(|text| Language::from_code(text.trim()));
    let language = saved.unwrap_or_else(system_language);
    CURRENT.with(|c| c.set(language));
    language
}

pub fn current() -> Language {
    CURRENT.with(Cell::get)
}

/// Switch language and remember it for this person.
pub fn choose(language: Language) {
    CURRENT.with(|c| c.set(language));
    let path = config_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, format!("{}\n", language.code()));
}

/// Translate an English interface text.
pub fn tr(text: &str) -> String {
    current().catalog().iter().find(|(key, _)| *key == text).map_or(text, |(_, t)| t).to_owned()
}

/// Translate and fill {name} placeholders.
pub fn trf(text: &str, values: &[(&str, &str)]) -> String {
    let mut result = tr(text);
    for (name, value) in values {
        result = result.replace(&format!("{{{name}}}"), value);
    }
    result
}

// English-keyed interface catalogs share the lookup module. Add new text to
// all three languages; trf fills named placeholders at runtime.
static PT: &[(&str, &str)] = &[
    ("Drive is open read-only", "A unidade está aberta somente para leitura"),
    ("Try write access again", "Tentar acesso de escrita novamente"),
    ("Permissions saved, but the drive is still open read-only. Creating, changing and deleting files remain disabled. Check the NTFS volume state before trying again.", "Permissões salvas, mas a unidade continua aberta somente para leitura. Criar, alterar e excluir arquivos permanece desativado. Verifique o estado do volume NTFS antes de tentar novamente."),
    ("Write permissions cannot override a read-only mount. Slate may refuse writing if the NTFS volume needs recovery, was left hibernated, or uses an unsupported layout. If Windows uses this drive, check it there and shut Windows down completely, then try again.", "Permissões de escrita não podem substituir uma montagem somente para leitura. O Slate pode recusar a escrita se o volume NTFS precisar de recuperação, estiver hibernado ou usar um formato não suportado. Se o Windows usa esta unidade, verifique-a nele e desligue o Windows completamente; depois tente novamente."),
    ("Saved. The drive is open with another NTFS driver. Close it in the file manager and open it again to use Slate permissions.", "Salvo. A unidade está aberta com outro driver NTFS. Feche-a no gerenciador de arquivos e abra-a novamente para usar as permissões do Slate."),
    ("Could not verify the new permissions:", "Não foi possível verificar as novas permissões:"),
    ("NTFS Permissions Manager", "Gerenciador de Permissões NTFS"),
    ("Language", "Idioma"),
    ("No access", "Sem acesso"),
    ("Cannot open this drive.", "Não pode abrir esta unidade."),
    ("Read only", "Somente leitura"),
    ("Can open and copy files, but cannot change anything.", "Pode abrir e copiar arquivos, mas não pode alterar nada."),
    ("Read & write", "Leitura e escrita"),
    ("Can add, change and delete files, like a standard Windows user.", "Pode adicionar, alterar e excluir arquivos, como um usuário padrão do Windows."),
    ("Full control", "Controle total"),
    ("Administrator of this drive: can do everything, including files Windows protects. Only one person per drive.", "Administrador desta unidade: pode fazer tudo, inclusive em arquivos que o Windows protege. Apenas uma pessoa por unidade."),
    ("All", "Todas"),
    ("Show all NTFS drives", "Mostrar todas as unidades NTFS"),
    ("SSD", "SSD"),
    ("Show only internal SSDs", "Mostrar apenas SSDs internos"),
    ("HDD", "HD"),
    ("Show only internal hard disks", "Mostrar apenas HDs internos"),
    ("Portable", "Portáteis"),
    ("Show only USB drives and memory cards", "Mostrar apenas unidades USB e cartões de memória"),
    ("Hard disk", "Disco rígido"),
    ("Portable drive", "Unidade portátil"),
    ("No NTFS drives found", "Nenhuma unidade NTFS encontrada"),
    ("No NTFS SSDs", "Nenhum SSD NTFS"),
    ("No NTFS hard disks", "Nenhum HD NTFS"),
    ("No portable NTFS drives", "Nenhuma unidade NTFS portátil"),
    ("{size} volume", "Volume de {size}"),
    ("Windows permissions", "Permissões do Windows"),
    ("as the owner", "como proprietário"),
    ("as a member of “{group}”", "como membro de “{group}”"),
    ("as everyone else", "como todos os demais"),
    ("The pkexec program is not installed.", "O programa pkexec não está instalado."),
    ("Authentication was cancelled.", "A autenticação foi cancelada."),
    ("No password dialog is available in this session.", "Nenhuma janela de senha está disponível nesta sessão."),
    ("Authentication failed.", "Falha na autenticação."),
    ("The administrator helper stopped (status {status}).", "O assistente de administrador parou (status {status})."),
    ("Read", "Leitura"),
    ("Open files and see what is in folders.", "Abrir arquivos e ver o conteúdo das pastas."),
    ("Write", "Escrita"),
    ("Create, change, rename and delete files and folders. Needs Read.", "Criar, alterar, renomear e excluir arquivos e pastas. Requer Leitura."),
    ("Execute", "Execução"),
    ("Run programs and scripts stored on the drive.", "Executar programas e scripts armazenados na unidade."),
    ("Owner", "Proprietário"),
    ("Group", "Grupo"),
    ("Everyone else", "Todos os demais"),
    ("Look for drives and people again", "Procurar unidades e pessoas novamente"),
    ("Save", "Salvar"),
    ("Save ({count})", "Salvar ({count})"),
    ("Save and apply the new permissions right away", "Salvar e aplicar as novas permissões imediatamente"),
    ("Unlock…", "Desbloquear…"),
    ("Drives", "Unidades"),
    ("Users", "Usuários"),
    ("Could not list drives: {error}", "Não foi possível listar as unidades: {error}"),
    ("Simple", "Simples"),
    ("Strict", "Estrito"),
    ("Unsaved changes", "Alterações não salvas"),
    ("Unknown person", "Pessoa desconhecida"),
    ("Changed", "Alterado"),
    ("Mounting permissions: pick an owner, a group and what everyone may do. The drive’s Windows permissions are kept, not used.", "Permissões de montagem: escolha um proprietário, um grupo e o que cada um pode fazer. As permissões do Windows na unidade são mantidas, mas não usadas."),
    ("Use the permissions Windows stored on the drive, with a level for each person. For drives shared with Windows users.", "Usa as permissões que o Windows gravou na unidade, com um nível para cada pessoa. Para unidades compartilhadas com usuários do Windows."),
    ("Whoever opens the drive", "Quem abrir a unidade"),
    ("Whoever opens the drive ({name})", "Quem abrir a unidade ({name})"),
    ("The owner’s own group", "O grupo do próprio proprietário"),
    ("{name} (everyone with a login)", "{name} (todos com login)"),
    ("Custom", "Personalizado"),
    ("Only the owner", "Somente o proprietário"),
    ("Owner and group", "Proprietário e grupo"),
    ("Everyone can read", "Todos podem ler"),
    ("Everyone can read and write", "Todos podem ler e escrever"),
    ("Group members are not listed", "Os membros do grupo não estão listados"),
    ("No people in this group yet", "Ainda não há pessoas neste grupo"),
    ("Members: {names}", "Membros: {names}"),
    ("Connect a drive formatted with NTFS (for example a Windows disk or a USB stick).", "Conecte uma unidade formatada em NTFS (por exemplo, um disco do Windows ou um pen drive)."),
    ("How access is decided", "Como o acesso é decidido"),
    ("Mounting permissions", "Permissões de montagem"),
    ("Apply to every file and folder while the drive is open on this computer.", "Valem para todos os arquivos e pastas enquanto a unidade estiver aberta neste computador."),
    ("Quick setup", "Configuração rápida"),
    ("Who can use this drive", "Quem pode usar esta unidade"),
    ("Each level becomes a Windows identity, and the drive’s own Windows permissions decide the rest.", "Cada nível vira uma identidade do Windows, e as permissões do Windows da própria unidade decidem o resto."),
    ("No user accounts", "Nenhuma conta de usuário"),
    ("People with a login on this computer appear here. Add one in Settings › System › Users.", "As pessoas com login neste computador aparecem aqui. Adicione uma em Configurações › Sistema › Usuários."),
    ("Groups: {groups}", "Grupos: {groups}"),
    ("Drives this person can use", "Unidades que esta pessoa pode usar"),
    ("Strict: Windows permissions", "Estrito: permissões do Windows"),
    ("Simple: {why}", "Simples: {why}"),
    ("Set by this drive’s mounting permissions. Change them on the Drives tab.", "Definido pelas permissões de montagem desta unidade. Altere-as na aba Unidades."),
    ("For drives using Simple mounting permissions, access comes from the owner, group and everyone-else settings on the Drives tab.", "Nas unidades com permissões de montagem Simples, o acesso vem das configurações de proprietário, grupo e demais pessoas na aba Unidades."),
    ("The group “{group}” can now read and write. Untick the boxes to change that.", "O grupo “{group}” agora pode ler e escrever. Desmarque as caixas para mudar isso."),
    ("Only one person can have full control of a drive, so {name} now has Read & write.", "Só uma pessoa pode ter controle total de uma unidade, então {name} agora tem Leitura e escrita."),
    ("Unlocked: you can change permissions. Click to lock.", "Desbloqueado: você pode alterar as permissões. Clique para bloquear."),
    ("Locked: click to unlock with {password}.", "Bloqueado: clique para desbloquear com {password}."),
    ("Waiting for {password}…", "Aguardando {password}…"),
    ("Discard unsaved changes?", "Descartar as alterações não salvas?"),
    ("Locking discards the changes you have not saved.", "Bloquear descarta as alterações que você não salvou."),
    ("Cancel", "Cancelar"),
    ("Discard and lock", "Descartar e bloquear"),
    ("Locked. You are viewing permissions only.", "Bloqueado. Você está apenas vendo as permissões."),
    ("{reason} You can view permissions, but changing them needs {password}.", "{reason} Você pode ver as permissões, mas para alterá-las é preciso {password}."),
    ("Saving…", "Salvando…"),
    ("The administrator session ended. Unlock again to save your changes.", "A sessão de administrador terminou. Desbloqueie de novo para salvar suas alterações."),
    ("Not saved: the administrator session ended.", "Não salvo: a sessão de administrador terminou."),
    ("Could not save permissions: {error}", "Não foi possível salvar as permissões: {error}"),
    ("Saved. {names} will use the new permissions the next time it is opened.", "Salvo. {names} usará as novas permissões na próxima vez que for aberta."),
    ("Saved. {names} will use the new permissions the next time they are opened.", "Salvo. {names} usarão as novas permissões na próxima vez que forem abertas."),
    ("Permissions saved and applied.", "Permissões salvas e aplicadas."),
    ("Save changes before closing?", "Salvar as alterações antes de fechar?"),
    ("Your permission changes have not been saved.", "Suas alterações de permissões não foram salvas."),
    ("Close without saving", "Fechar sem salvar"),
    ("the root password", "a senha de root"),
    ("an administrator password", "a senha de um administrador"),
    ("{count} of {total} drives", "{count} de {total} unidades"),
    ("{count} of 1 drive", "{count} de 1 unidade"),
    ("{name} (you)", "{name} (você)"),
    ("Saved. It applies the next time the drive is connected.", "Salvo. Vale a partir da próxima vez que a unidade for conectada."),
    ("Saved. It applies the next time the drive is opened.", "Salvo. Vale a partir da próxima vez que a unidade for aberta."),
    ("Saved, but the drive is in use. Close its files and windows, then click Save again (or reconnect the drive).", "Salvo, mas a unidade está em uso. Feche os arquivos e janelas dela e clique em Salvar de novo (ou reconecte a unidade)."),
    ("Permissions updated.", "Permissões atualizadas."),
    ("There are no changes to save.", "Não há alterações para salvar."),
    ("Saved. Restart the computer once to load the updated driver; after that, changes apply instantly.", "Salvo. Reinicie o computador uma vez para carregar o driver atualizado; depois disso, as alterações valem na hora."),
    ("Could not apply the new permissions:", "Não foi possível aplicar as novas permissões:"),
    ("Could not save permissions:", "Não foi possível salvar as permissões:"),
    ("Double-click to rename", "Clique duas vezes para renomear"),
    ("Only an administrator can rename drives.", "Somente um administrador pode renomear unidades."),
    ("Renaming the drive…", "Renomeando a unidade…"),
    ("Drive renamed.", "Unidade renomeada."),
    ("Could not rename the drive: {error}", "Não foi possível renomear a unidade: {error}"),
    ("Could not rename the drive:", "Não foi possível renomear a unidade:"),
    ("Not renamed: the administrator session ended.", "Não renomeada: a sessão de administrador terminou."),
    ("Type a name for the drive.", "Digite um nome para a unidade."),
    ("The name cannot contain control characters.", "O nome não pode conter caracteres de controle."),
    ("The name can have at most 32 characters.", "O nome pode ter no máximo 32 caracteres."),
    ("The drive is no longer connected.", "A unidade não está mais conectada."),
    ("The drive is open with another NTFS driver. Close it in the file manager and try again.", "A unidade está aberta com outro driver NTFS. Feche-a no gerenciador de arquivos e tente novamente."),
    ("The drive is open read-only, so it cannot be renamed. If Windows uses Fast Startup or hibernation, shut Windows down completely first.", "A unidade está aberta somente para leitura, então não pode ser renomeada. Se o Windows usa a Inicialização Rápida ou a hibernação, desligue o Windows completamente primeiro."),
    ("Restart the computer once to load the updated driver; after that, drives can be renamed.", "Reinicie o computador uma vez para carregar o driver atualizado; depois disso, as unidades podem ser renomeadas."),
];

static ES: &[(&str, &str)] = &[
    ("Drive is open read-only", "La unidad está abierta en modo de solo lectura"),
    ("Try write access again", "Volver a intentar el acceso de escritura"),
    ("Permissions saved, but the drive is still open read-only. Creating, changing and deleting files remain disabled. Check the NTFS volume state before trying again.", "Permisos guardados, pero la unidad sigue abierta en modo de solo lectura. Crear, modificar y eliminar archivos sigue desactivado. Compruebe el estado del volumen NTFS antes de volver a intentarlo."),
    ("Write permissions cannot override a read-only mount. Slate may refuse writing if the NTFS volume needs recovery, was left hibernated, or uses an unsupported layout. If Windows uses this drive, check it there and shut Windows down completely, then try again.", "Los permisos de escritura no pueden anular un montaje de solo lectura. Slate puede rechazar la escritura si el volumen NTFS necesita recuperación, quedó hibernado o usa un formato no compatible. Si Windows usa esta unidad, compruébela allí y apague Windows por completo; luego vuelva a intentarlo."),
    ("Saved. The drive is open with another NTFS driver. Close it in the file manager and open it again to use Slate permissions.", "Guardado. La unidad está abierta con otro controlador NTFS. Ciérrela en el gestor de archivos y ábrala de nuevo para usar los permisos de Slate."),
    ("Could not verify the new permissions:", "No se pudieron verificar los nuevos permisos:"),
    ("NTFS Permissions Manager", "Gestor de permisos NTFS"),
    ("Language", "Idioma"),
    ("No access", "Sin acceso"),
    ("Cannot open this drive.", "No puede abrir esta unidad."),
    ("Read only", "Solo lectura"),
    ("Can open and copy files, but cannot change anything.", "Puede abrir y copiar archivos, pero no puede cambiar nada."),
    ("Read & write", "Lectura y escritura"),
    ("Can add, change and delete files, like a standard Windows user.", "Puede añadir, cambiar y eliminar archivos, como un usuario estándar de Windows."),
    ("Full control", "Control total"),
    ("Administrator of this drive: can do everything, including files Windows protects. Only one person per drive.", "Administrador de esta unidad: puede hacerlo todo, incluso con archivos que Windows protege. Solo una persona por unidad."),
    ("All", "Todas"),
    ("Show all NTFS drives", "Mostrar todas las unidades NTFS"),
    ("SSD", "SSD"),
    ("Show only internal SSDs", "Mostrar solo SSD internos"),
    ("HDD", "HDD"),
    ("Show only internal hard disks", "Mostrar solo discos duros internos"),
    ("Portable", "Portátiles"),
    ("Show only USB drives and memory cards", "Mostrar solo unidades USB y tarjetas de memoria"),
    ("Hard disk", "Disco duro"),
    ("Portable drive", "Unidad portátil"),
    ("No NTFS drives found", "No se encontraron unidades NTFS"),
    ("No NTFS SSDs", "No hay SSD NTFS"),
    ("No NTFS hard disks", "No hay discos duros NTFS"),
    ("No portable NTFS drives", "No hay unidades NTFS portátiles"),
    ("{size} volume", "Volumen de {size}"),
    ("Windows permissions", "Permisos de Windows"),
    ("as the owner", "como propietario"),
    ("as a member of “{group}”", "como miembro de “{group}”"),
    ("as everyone else", "como el resto"),
    ("The pkexec program is not installed.", "El programa pkexec no está instalado."),
    ("Authentication was cancelled.", "Se canceló la autenticación."),
    ("No password dialog is available in this session.", "No hay ninguna ventana de contraseña disponible en esta sesión."),
    ("Authentication failed.", "La autenticación falló."),
    ("The administrator helper stopped (status {status}).", "El asistente de administrador se detuvo (estado {status})."),
    ("Read", "Lectura"),
    ("Open files and see what is in folders.", "Abrir archivos y ver el contenido de las carpetas."),
    ("Write", "Escritura"),
    ("Create, change, rename and delete files and folders. Needs Read.", "Crear, cambiar, renombrar y eliminar archivos y carpetas. Requiere Lectura."),
    ("Execute", "Ejecución"),
    ("Run programs and scripts stored on the drive.", "Ejecutar programas y scripts guardados en la unidad."),
    ("Owner", "Propietario"),
    ("Group", "Grupo"),
    ("Everyone else", "Todos los demás"),
    ("Look for drives and people again", "Buscar unidades y personas de nuevo"),
    ("Save", "Guardar"),
    ("Save ({count})", "Guardar ({count})"),
    ("Save and apply the new permissions right away", "Guardar y aplicar los nuevos permisos de inmediato"),
    ("Unlock…", "Desbloquear…"),
    ("Drives", "Unidades"),
    ("Users", "Usuarios"),
    ("Could not list drives: {error}", "No se pudieron listar las unidades: {error}"),
    ("Simple", "Simple"),
    ("Strict", "Estricto"),
    ("Unsaved changes", "Cambios sin guardar"),
    ("Unknown person", "Persona desconocida"),
    ("Changed", "Cambiado"),
    ("Mounting permissions: pick an owner, a group and what everyone may do. The drive’s Windows permissions are kept, not used.", "Permisos de montaje: elige un propietario, un grupo y lo que puede hacer cada uno. Los permisos de Windows de la unidad se conservan, pero no se usan."),
    ("Use the permissions Windows stored on the drive, with a level for each person. For drives shared with Windows users.", "Usa los permisos que Windows guardó en la unidad, con un nivel para cada persona. Para unidades compartidas con usuarios de Windows."),
    ("Whoever opens the drive", "Quien abra la unidad"),
    ("Whoever opens the drive ({name})", "Quien abra la unidad ({name})"),
    ("The owner’s own group", "El grupo propio del propietario"),
    ("{name} (everyone with a login)", "{name} (todos con sesión)"),
    ("Custom", "Personalizado"),
    ("Only the owner", "Solo el propietario"),
    ("Owner and group", "Propietario y grupo"),
    ("Everyone can read", "Todos pueden leer"),
    ("Everyone can read and write", "Todos pueden leer y escribir"),
    ("Group members are not listed", "Los miembros del grupo no aparecen"),
    ("No people in this group yet", "Todavía no hay personas en este grupo"),
    ("Members: {names}", "Miembros: {names}"),
    ("Connect a drive formatted with NTFS (for example a Windows disk or a USB stick).", "Conecta una unidad formateada en NTFS (por ejemplo, un disco de Windows o una memoria USB)."),
    ("How access is decided", "Cómo se decide el acceso"),
    ("Mounting permissions", "Permisos de montaje"),
    ("Apply to every file and folder while the drive is open on this computer.", "Se aplican a todos los archivos y carpetas mientras la unidad está abierta en este equipo."),
    ("Quick setup", "Configuración rápida"),
    ("Who can use this drive", "Quién puede usar esta unidad"),
    ("Each level becomes a Windows identity, and the drive’s own Windows permissions decide the rest.", "Cada nivel se convierte en una identidad de Windows, y los propios permisos de Windows de la unidad deciden el resto."),
    ("No user accounts", "No hay cuentas de usuario"),
    ("People with a login on this computer appear here. Add one in Settings › System › Users.", "Aquí aparecen las personas con sesión en este equipo. Añade una en Configuración › Sistema › Usuarios."),
    ("Groups: {groups}", "Grupos: {groups}"),
    ("Drives this person can use", "Unidades que esta persona puede usar"),
    ("Strict: Windows permissions", "Estricto: permisos de Windows"),
    ("Simple: {why}", "Simple: {why}"),
    ("Set by this drive’s mounting permissions. Change them on the Drives tab.", "Lo definen los permisos de montaje de esta unidad. Cámbialos en la pestaña Unidades."),
    ("For drives using Simple mounting permissions, access comes from the owner, group and everyone-else settings on the Drives tab.", "En las unidades con permisos de montaje Simples, el acceso viene de los ajustes de propietario, grupo y demás personas en la pestaña Unidades."),
    ("The group “{group}” can now read and write. Untick the boxes to change that.", "El grupo “{group}” ahora puede leer y escribir. Desmarca las casillas para cambiarlo."),
    ("Only one person can have full control of a drive, so {name} now has Read & write.", "Solo una persona puede tener control total de una unidad, así que {name} ahora tiene Lectura y escritura."),
    ("Unlocked: you can change permissions. Click to lock.", "Desbloqueado: puedes cambiar los permisos. Haz clic para bloquear."),
    ("Locked: click to unlock with {password}.", "Bloqueado: haz clic para desbloquear con {password}."),
    ("Waiting for {password}…", "Esperando {password}…"),
    ("Discard unsaved changes?", "¿Descartar los cambios sin guardar?"),
    ("Locking discards the changes you have not saved.", "Al bloquear se descartan los cambios que no has guardado."),
    ("Cancel", "Cancelar"),
    ("Discard and lock", "Descartar y bloquear"),
    ("Locked. You are viewing permissions only.", "Bloqueado. Solo estás viendo los permisos."),
    ("{reason} You can view permissions, but changing them needs {password}.", "{reason} Puedes ver los permisos, pero para cambiarlos se necesita {password}."),
    ("Saving…", "Guardando…"),
    ("The administrator session ended. Unlock again to save your changes.", "La sesión de administrador terminó. Desbloquea de nuevo para guardar tus cambios."),
    ("Not saved: the administrator session ended.", "No guardado: la sesión de administrador terminó."),
    ("Could not save permissions: {error}", "No se pudieron guardar los permisos: {error}"),
    ("Saved. {names} will use the new permissions the next time it is opened.", "Guardado. {names} usará los nuevos permisos la próxima vez que se abra."),
    ("Saved. {names} will use the new permissions the next time they are opened.", "Guardado. {names} usarán los nuevos permisos la próxima vez que se abran."),
    ("Permissions saved and applied.", "Permisos guardados y aplicados."),
    ("Save changes before closing?", "¿Guardar los cambios antes de cerrar?"),
    ("Your permission changes have not been saved.", "Tus cambios de permisos no se han guardado."),
    ("Close without saving", "Cerrar sin guardar"),
    ("the root password", "la contraseña de root"),
    ("an administrator password", "la contraseña de un administrador"),
    ("{count} of {total} drives", "{count} de {total} unidades"),
    ("{count} of 1 drive", "{count} de 1 unidad"),
    ("{name} (you)", "{name} (tú)"),
    ("Saved. It applies the next time the drive is connected.", "Guardado. Se aplica la próxima vez que se conecte la unidad."),
    ("Saved. It applies the next time the drive is opened.", "Guardado. Se aplica la próxima vez que se abra la unidad."),
    ("Saved, but the drive is in use. Close its files and windows, then click Save again (or reconnect the drive).", "Guardado, pero la unidad está en uso. Cierra sus archivos y ventanas y vuelve a hacer clic en Guardar (o reconecta la unidad)."),
    ("Permissions updated.", "Permisos actualizados."),
    ("There are no changes to save.", "No hay cambios para guardar."),
    ("Saved. Restart the computer once to load the updated driver; after that, changes apply instantly.", "Guardado. Reinicia el equipo una vez para cargar el controlador actualizado; después, los cambios se aplican al instante."),
    ("Could not apply the new permissions:", "No se pudieron aplicar los nuevos permisos:"),
    ("Could not save permissions:", "No se pudieron guardar los permisos:"),
    ("Double-click to rename", "Haga doble clic para cambiar el nombre"),
    ("Only an administrator can rename drives.", "Solo un administrador puede cambiar el nombre de las unidades."),
    ("Renaming the drive…", "Cambiando el nombre de la unidad…"),
    ("Drive renamed.", "Nombre de la unidad cambiado."),
    ("Could not rename the drive: {error}", "No se pudo cambiar el nombre de la unidad: {error}"),
    ("Could not rename the drive:", "No se pudo cambiar el nombre de la unidad:"),
    ("Not renamed: the administrator session ended.", "No se cambió el nombre: la sesión de administrador terminó."),
    ("Type a name for the drive.", "Escriba un nombre para la unidad."),
    ("The name cannot contain control characters.", "El nombre no puede contener caracteres de control."),
    ("The name can have at most 32 characters.", "El nombre puede tener como máximo 32 caracteres."),
    ("The drive is no longer connected.", "La unidad ya no está conectada."),
    ("The drive is open with another NTFS driver. Close it in the file manager and try again.", "La unidad está abierta con otro controlador NTFS. Ciérrela en el gestor de archivos e inténtelo de nuevo."),
    ("The drive is open read-only, so it cannot be renamed. If Windows uses Fast Startup or hibernation, shut Windows down completely first.", "La unidad está abierta en modo de solo lectura, así que no se puede cambiar su nombre. Si Windows usa el Inicio rápido o la hibernación, apague Windows por completo primero."),
    ("Restart the computer once to load the updated driver; after that, drives can be renamed.", "Reinicie el equipo una vez para cargar el controlador actualizado; después, podrá cambiar el nombre de las unidades."),
];

static EL: &[(&str, &str)] = &[
    ("Drive is open read-only", "Η μονάδα είναι ανοιχτή μόνο για ανάγνωση"),
    ("Try write access again", "Δοκιμή πρόσβασης εγγραφής ξανά"),
    ("Permissions saved, but the drive is still open read-only. Creating, changing and deleting files remain disabled. Check the NTFS volume state before trying again.", "Τα δικαιώματα αποθηκεύτηκαν, αλλά η μονάδα παραμένει ανοιχτή μόνο για ανάγνωση. Η δημιουργία, αλλαγή και διαγραφή αρχείων παραμένουν απενεργοποιημένες. Ελέγξτε την κατάσταση του τόμου NTFS πριν δοκιμάσετε ξανά."),
    ("Write permissions cannot override a read-only mount. Slate may refuse writing if the NTFS volume needs recovery, was left hibernated, or uses an unsupported layout. If Windows uses this drive, check it there and shut Windows down completely, then try again.", "Τα δικαιώματα εγγραφής δεν μπορούν να παρακάμψουν μια προσάρτηση μόνο για ανάγνωση. Το Slate μπορεί να αρνηθεί την εγγραφή αν ο τόμος NTFS χρειάζεται ανάκτηση, έχει μείνει σε αδρανοποίηση ή χρησιμοποιεί μη υποστηριζόμενη διάταξη. Αν τα Windows χρησιμοποιούν αυτή τη μονάδα, ελέγξτε την εκεί και τερματίστε πλήρως τα Windows, μετά δοκιμάστε ξανά."),
    ("Saved. The drive is open with another NTFS driver. Close it in the file manager and open it again to use Slate permissions.", "Αποθηκεύτηκε. Η μονάδα είναι ανοιχτή με άλλο οδηγό NTFS. Κλείστε την στον διαχειριστή αρχείων και ανοίξτε την ξανά για να χρησιμοποιήσετε τα δικαιώματα του Slate."),
    ("Could not verify the new permissions:", "Δεν ήταν δυνατή η επαλήθευση των νέων δικαιωμάτων:"),
    ("NTFS Permissions Manager", "Διαχείριση δικαιωμάτων NTFS"),
    ("Language", "Γλώσσα"),
    ("No access", "Χωρίς πρόσβαση"),
    ("Cannot open this drive.", "Δεν μπορεί να ανοίξει αυτή τη μονάδα."),
    ("Read only", "Μόνο ανάγνωση"),
    ("Can open and copy files, but cannot change anything.", "Μπορεί να ανοίγει και να αντιγράφει αρχεία, αλλά δεν μπορεί να αλλάξει τίποτα."),
    ("Read & write", "Ανάγνωση και εγγραφή"),
    ("Can add, change and delete files, like a standard Windows user.", "Μπορεί να προσθέτει, να αλλάζει και να διαγράφει αρχεία, όπως ένας τυπικός χρήστης των Windows."),
    ("Full control", "Πλήρης έλεγχος"),
    ("Administrator of this drive: can do everything, including files Windows protects. Only one person per drive.", "Διαχειριστής αυτής της μονάδας: μπορεί να κάνει τα πάντα, ακόμη και σε αρχεία που προστατεύουν τα Windows. Μόνο ένα άτομο ανά μονάδα."),
    ("All", "Όλες"),
    ("Show all NTFS drives", "Εμφάνιση όλων των μονάδων NTFS"),
    ("SSD", "SSD"),
    ("Show only internal SSDs", "Εμφάνιση μόνο εσωτερικών SSD"),
    ("HDD", "HDD"),
    ("Show only internal hard disks", "Εμφάνιση μόνο εσωτερικών σκληρών δίσκων"),
    ("Portable", "Φορητές"),
    ("Show only USB drives and memory cards", "Εμφάνιση μόνο μονάδων USB και καρτών μνήμης"),
    ("Hard disk", "Σκληρός δίσκος"),
    ("Portable drive", "Φορητή μονάδα"),
    ("No NTFS drives found", "Δεν βρέθηκαν μονάδες NTFS"),
    ("No NTFS SSDs", "Δεν υπάρχουν SSD NTFS"),
    ("No NTFS hard disks", "Δεν υπάρχουν σκληροί δίσκοι NTFS"),
    ("No portable NTFS drives", "Δεν υπάρχουν φορητές μονάδες NTFS"),
    ("{size} volume", "Τόμος {size}"),
    ("Windows permissions", "Δικαιώματα Windows"),
    ("as the owner", "ως κάτοχος"),
    ("as a member of “{group}”", "ως μέλος της ομάδας «{group}»"),
    ("as everyone else", "ως όλοι οι άλλοι"),
    ("The pkexec program is not installed.", "Το πρόγραμμα pkexec δεν είναι εγκατεστημένο."),
    ("Authentication was cancelled.", "Ο έλεγχος ταυτότητας ακυρώθηκε."),
    ("No password dialog is available in this session.", "Δεν υπάρχει διαθέσιμο παράθυρο κωδικού σε αυτή τη συνεδρία."),
    ("Authentication failed.", "Ο έλεγχος ταυτότητας απέτυχε."),
    ("The administrator helper stopped (status {status}).", "Ο βοηθός διαχειριστή σταμάτησε (κατάσταση {status})."),
    ("Read", "Ανάγνωση"),
    ("Open files and see what is in folders.", "Άνοιγμα αρχείων και προβολή του περιεχομένου των φακέλων."),
    ("Write", "Εγγραφή"),
    ("Create, change, rename and delete files and folders. Needs Read.", "Δημιουργία, αλλαγή, μετονομασία και διαγραφή αρχείων και φακέλων. Απαιτεί Ανάγνωση."),
    ("Execute", "Εκτέλεση"),
    ("Run programs and scripts stored on the drive.", "Εκτέλεση προγραμμάτων και σεναρίων που είναι αποθηκευμένα στη μονάδα."),
    ("Owner", "Κάτοχος"),
    ("Group", "Ομάδα"),
    ("Everyone else", "Όλοι οι άλλοι"),
    ("Look for drives and people again", "Αναζήτηση μονάδων και ατόμων ξανά"),
    ("Save", "Αποθήκευση"),
    ("Save ({count})", "Αποθήκευση ({count})"),
    ("Save and apply the new permissions right away", "Αποθήκευση και άμεση εφαρμογή των νέων δικαιωμάτων"),
    ("Unlock…", "Ξεκλείδωμα…"),
    ("Drives", "Μονάδες"),
    ("Users", "Χρήστες"),
    ("Could not list drives: {error}", "Δεν ήταν δυνατή η εμφάνιση των μονάδων: {error}"),
    ("Simple", "Απλή"),
    ("Strict", "Αυστηρή"),
    ("Unsaved changes", "Μη αποθηκευμένες αλλαγές"),
    ("Unknown person", "Άγνωστο άτομο"),
    ("Changed", "Άλλαξε"),
    ("Mounting permissions: pick an owner, a group and what everyone may do. The drive’s Windows permissions are kept, not used.", "Δικαιώματα προσάρτησης: επιλέξτε κάτοχο, ομάδα και τι μπορούν να κάνουν όλοι. Τα δικαιώματα Windows της μονάδας διατηρούνται, αλλά δεν χρησιμοποιούνται."),
    ("Use the permissions Windows stored on the drive, with a level for each person. For drives shared with Windows users.", "Χρησιμοποιεί τα δικαιώματα που αποθήκευσαν τα Windows στη μονάδα, με ένα επίπεδο για κάθε άτομο. Για μονάδες που μοιράζεστε με χρήστες των Windows."),
    ("Whoever opens the drive", "Όποιος ανοίγει τη μονάδα"),
    ("Whoever opens the drive ({name})", "Όποιος ανοίγει τη μονάδα ({name})"),
    ("The owner’s own group", "Η ομάδα του ίδιου του κατόχου"),
    ("{name} (everyone with a login)", "{name} (όλοι με λογαριασμό)"),
    ("Custom", "Προσαρμογή"),
    ("Only the owner", "Μόνο ο κάτοχος"),
    ("Owner and group", "Κάτοχος και ομάδα"),
    ("Everyone can read", "Όλοι μπορούν να διαβάζουν"),
    ("Everyone can read and write", "Όλοι μπορούν να διαβάζουν και να γράφουν"),
    ("Group members are not listed", "Τα μέλη της ομάδας δεν εμφανίζονται"),
    ("No people in this group yet", "Δεν υπάρχουν ακόμη άτομα σε αυτή την ομάδα"),
    ("Members: {names}", "Μέλη: {names}"),
    ("Connect a drive formatted with NTFS (for example a Windows disk or a USB stick).", "Συνδέστε μια μονάδα μορφοποιημένη σε NTFS (για παράδειγμα έναν δίσκο Windows ή ένα στικάκι USB)."),
    ("How access is decided", "Πώς αποφασίζεται η πρόσβαση"),
    ("Mounting permissions", "Δικαιώματα προσάρτησης"),
    ("Apply to every file and folder while the drive is open on this computer.", "Ισχύουν για όλα τα αρχεία και τους φακέλους όσο η μονάδα είναι ανοιχτή σε αυτόν τον υπολογιστή."),
    ("Quick setup", "Γρήγορη ρύθμιση"),
    ("Who can use this drive", "Ποιος μπορεί να χρησιμοποιεί αυτή τη μονάδα"),
    ("Each level becomes a Windows identity, and the drive’s own Windows permissions decide the rest.", "Κάθε επίπεδο γίνεται μια ταυτότητα Windows, και τα δικαιώματα Windows της ίδιας της μονάδας αποφασίζουν τα υπόλοιπα."),
    ("No user accounts", "Δεν υπάρχουν λογαριασμοί χρηστών"),
    ("People with a login on this computer appear here. Add one in Settings › System › Users.", "Εδώ εμφανίζονται τα άτομα που έχουν λογαριασμό σε αυτόν τον υπολογιστή. Προσθέστε έναν στις Ρυθμίσεις › Σύστημα › Χρήστες."),
    ("Groups: {groups}", "Ομάδες: {groups}"),
    ("Drives this person can use", "Μονάδες που μπορεί να χρησιμοποιεί αυτό το άτομο"),
    ("Strict: Windows permissions", "Αυστηρή: δικαιώματα Windows"),
    ("Simple: {why}", "Απλή: {why}"),
    ("Set by this drive’s mounting permissions. Change them on the Drives tab.", "Ορίζεται από τα δικαιώματα προσάρτησης αυτής της μονάδας. Αλλάξτε τα στην καρτέλα Μονάδες."),
    ("For drives using Simple mounting permissions, access comes from the owner, group and everyone-else settings on the Drives tab.", "Στις μονάδες με Απλά δικαιώματα προσάρτησης, η πρόσβαση προκύπτει από τις ρυθμίσεις κατόχου, ομάδας και όλων των άλλων στην καρτέλα Μονάδες."),
    ("The group “{group}” can now read and write. Untick the boxes to change that.", "Η ομάδα «{group}» μπορεί τώρα να διαβάζει και να γράφει. Καταργήστε την επιλογή των πλαισίων για να το αλλάξετε."),
    ("Only one person can have full control of a drive, so {name} now has Read & write.", "Μόνο ένα άτομο μπορεί να έχει πλήρη έλεγχο μιας μονάδας, οπότε ο/η {name} έχει τώρα Ανάγνωση και εγγραφή."),
    ("Unlocked: you can change permissions. Click to lock.", "Ξεκλείδωτο: μπορείτε να αλλάξετε δικαιώματα. Κάντε κλικ για κλείδωμα."),
    ("Locked: click to unlock with {password}.", "Κλειδωμένο: κάντε κλικ για ξεκλείδωμα με {password}."),
    ("Waiting for {password}…", "Αναμονή για {password}…"),
    ("Discard unsaved changes?", "Απόρριψη των μη αποθηκευμένων αλλαγών;"),
    ("Locking discards the changes you have not saved.", "Το κλείδωμα απορρίπτει τις αλλαγές που δεν αποθηκεύσατε."),
    ("Cancel", "Ακύρωση"),
    ("Discard and lock", "Απόρριψη και κλείδωμα"),
    ("Locked. You are viewing permissions only.", "Κλειδωμένο. Βλέπετε μόνο τα δικαιώματα."),
    ("{reason} You can view permissions, but changing them needs {password}.", "{reason} Μπορείτε να δείτε τα δικαιώματα, αλλά για να τα αλλάξετε χρειάζεστε {password}."),
    ("Saving…", "Αποθήκευση…"),
    ("The administrator session ended. Unlock again to save your changes.", "Η συνεδρία διαχειριστή έληξε. Ξεκλειδώστε ξανά για να αποθηκεύσετε τις αλλαγές σας."),
    ("Not saved: the administrator session ended.", "Δεν αποθηκεύτηκε: η συνεδρία διαχειριστή έληξε."),
    ("Could not save permissions: {error}", "Δεν ήταν δυνατή η αποθήκευση των δικαιωμάτων: {error}"),
    ("Saved. {names} will use the new permissions the next time it is opened.", "Αποθηκεύτηκε. Η μονάδα {names} θα χρησιμοποιήσει τα νέα δικαιώματα την επόμενη φορά που θα ανοίξει."),
    ("Saved. {names} will use the new permissions the next time they are opened.", "Αποθηκεύτηκε. Οι μονάδες {names} θα χρησιμοποιήσουν τα νέα δικαιώματα την επόμενη φορά που θα ανοίξουν."),
    ("Permissions saved and applied.", "Τα δικαιώματα αποθηκεύτηκαν και εφαρμόστηκαν."),
    ("Save changes before closing?", "Αποθήκευση αλλαγών πριν από το κλείσιμο;"),
    ("Your permission changes have not been saved.", "Οι αλλαγές δικαιωμάτων σας δεν έχουν αποθηκευτεί."),
    ("Close without saving", "Κλείσιμο χωρίς αποθήκευση"),
    ("the root password", "τον κωδικό του root"),
    ("an administrator password", "τον κωδικό ενός διαχειριστή"),
    ("{count} of {total} drives", "{count} από {total} μονάδες"),
    ("{count} of 1 drive", "{count} από 1 μονάδα"),
    ("{name} (you)", "{name} (εσείς)"),
    ("Saved. It applies the next time the drive is connected.", "Αποθηκεύτηκε. Θα ισχύσει την επόμενη φορά που θα συνδεθεί η μονάδα."),
    ("Saved. It applies the next time the drive is opened.", "Αποθηκεύτηκε. Θα ισχύσει την επόμενη φορά που θα ανοίξει η μονάδα."),
    ("Saved, but the drive is in use. Close its files and windows, then click Save again (or reconnect the drive).", "Αποθηκεύτηκε, αλλά η μονάδα χρησιμοποιείται. Κλείστε τα αρχεία και τα παράθυρά της και κάντε ξανά κλικ στην Αποθήκευση (ή συνδέστε ξανά τη μονάδα)."),
    ("Permissions updated.", "Τα δικαιώματα ενημερώθηκαν."),
    ("There are no changes to save.", "Δεν υπάρχουν αλλαγές για αποθήκευση."),
    ("Saved. Restart the computer once to load the updated driver; after that, changes apply instantly.", "Αποθηκεύτηκε. Επανεκκινήστε τον υπολογιστή μία φορά για να φορτωθεί το ενημερωμένο πρόγραμμα οδήγησης· μετά οι αλλαγές ισχύουν αμέσως."),
    ("Could not apply the new permissions:", "Δεν ήταν δυνατή η εφαρμογή των νέων δικαιωμάτων:"),
    ("Could not save permissions:", "Δεν ήταν δυνατή η αποθήκευση των δικαιωμάτων:"),
    ("Double-click to rename", "Κάντε διπλό κλικ για μετονομασία"),
    ("Only an administrator can rename drives.", "Μόνο ένας διαχειριστής μπορεί να μετονομάσει μονάδες δίσκου."),
    ("Renaming the drive…", "Μετονομασία της μονάδας…"),
    ("Drive renamed.", "Η μονάδα μετονομάστηκε."),
    ("Could not rename the drive: {error}", "Δεν ήταν δυνατή η μετονομασία της μονάδας: {error}"),
    ("Could not rename the drive:", "Δεν ήταν δυνατή η μετονομασία της μονάδας:"),
    ("Not renamed: the administrator session ended.", "Δεν μετονομάστηκε: η συνεδρία διαχειριστή έληξε."),
    ("Type a name for the drive.", "Πληκτρολογήστε ένα όνομα για τη μονάδα."),
    ("The name cannot contain control characters.", "Το όνομα δεν μπορεί να περιέχει χαρακτήρες ελέγχου."),
    ("The name can have at most 32 characters.", "Το όνομα μπορεί να έχει έως 32 χαρακτήρες."),
    ("The drive is no longer connected.", "Η μονάδα δεν είναι πλέον συνδεδεμένη."),
    ("The drive is open with another NTFS driver. Close it in the file manager and try again.", "Η μονάδα είναι ανοιχτή με άλλο πρόγραμμα οδήγησης NTFS. Κλείστε την στη διαχείριση αρχείων και δοκιμάστε ξανά."),
    ("The drive is open read-only, so it cannot be renamed. If Windows uses Fast Startup or hibernation, shut Windows down completely first.", "Η μονάδα είναι ανοιχτή μόνο για ανάγνωση, οπότε δεν μπορεί να μετονομαστεί. Αν τα Windows χρησιμοποιούν Γρήγορη εκκίνηση ή αδρανοποίηση, τερματίστε πρώτα πλήρως τα Windows."),
    ("Restart the computer once to load the updated driver; after that, drives can be renamed.", "Επανεκκινήστε τον υπολογιστή μία φορά για να φορτωθεί το ενημερωμένο πρόγραμμα οδήγησης· μετά από αυτό, οι μονάδες μπορούν να μετονομαστούν."),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogs_are_complete_and_placeholders_match() {
        let placeholders = |s: &str| {
            let mut names: Vec<String> =
                s.split('{').skip(1).filter_map(|p| p.split('}').next()).map(str::to_owned).collect();
            names.sort();
            names
        };
        let keys: Vec<&str> = PT.iter().map(|(k, _)| *k).collect();
        for catalog in [PT, ES, EL] {
            assert_eq!(catalog.len(), keys.len());
            for (key, text) in catalog {
                assert!(keys.contains(key), "{key}");
                assert_eq!(placeholders(key), placeholders(text), "{key}");
            }
        }
    }

    #[test]
    fn translation_and_fallback() {
        CURRENT.with(|c| c.set(Language::Pt));
        assert_eq!(tr("Save"), "Salvar");
        assert_eq!(trf("Save ({count})", &[("count", "3")]), "Salvar (3)");
        assert_eq!(tr("Not in any catalog"), "Not in any catalog");
        CURRENT.with(|c| c.set(Language::El));
        assert_eq!(tr("Drives"), "Μονάδες");
        CURRENT.with(|c| c.set(Language::En));
        assert_eq!(tr("Drives"), "Drives");
    }
}
