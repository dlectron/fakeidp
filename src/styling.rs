use std::path::{Path, PathBuf};

/// URL prefix the styling folder is served under.
pub const URL_PREFIX: &str = "/styling";

/// Stylesheet loaded after `main.css`, so its rules win over the defaults.
const STYLESHEET: &str = "custom.css";

/// Image types a logo or background may be, in the order they are looked for.
const IMAGE_EXTENSIONS: [&str; 6] = ["svg", "png", "webp", "jpg", "jpeg", "gif"];

const DEFAULT_LOGO: &str = "/static/logo.png";

/// Restyles the login screen from a folder of well-known files:
///
/// - `custom.css`, linked after the built-in stylesheet
/// - `logo.<ext>`, replacing the logo in the navbar
/// - `background.<ext>`, covering the page behind the login panel
///
/// Every file is optional. The folder is looked at on each render rather than
/// once at startup, so a file dropped into a mounted folder shows up on the next
/// page load without a restart.
#[derive(Clone, Debug, Default)]
pub struct Styling {
    folder: Option<PathBuf>,
}

/// The parts of the login page a styling folder changes, ready to drop into the template.
#[derive(Debug, PartialEq)]
pub struct Branding {
    pub stylesheet: String,
    pub logo: String,
    /// Extra classes on `<body>`, each with a leading space.
    pub body_class: String,
    /// A complete ` style="..."` attribute for `<body>`, or nothing.
    pub body_style: String,
}

impl Styling {
    pub fn new(folder: Option<PathBuf>) -> Self {
        Self { folder }
    }

    pub fn folder(&self) -> Option<&Path> {
        self.folder.as_deref()
    }

    pub fn branding(&self) -> Branding {
        let folder = match &self.folder {
            Some(folder) => folder,
            None => return Branding::default(),
        };
        let stylesheet = if folder.join(STYLESHEET).is_file() {
            format!(
                r#"<link href="{}/{}" rel="stylesheet">"#,
                URL_PREFIX, STYLESHEET
            )
        } else {
            String::new()
        };
        let logo = find_image(folder, "logo")
            .map(|file| format!("{}/{}", URL_PREFIX, file))
            .unwrap_or_else(|| DEFAULT_LOGO.to_string());
        // The rest of the background (size, position) lives in main.css under
        // .theme-body--image, where custom.css can override it.
        let (body_class, body_style) = match find_image(folder, "background") {
            Some(file) => (
                " theme-body--image".to_string(),
                format!(
                    r#" style="background-image: url('{}/{}')""#,
                    URL_PREFIX, file
                ),
            ),
            None => (String::new(), String::new()),
        };
        Branding {
            stylesheet,
            logo,
            body_class,
            body_style,
        }
    }
}

impl Default for Branding {
    fn default() -> Self {
        Self {
            stylesheet: String::new(),
            logo: DEFAULT_LOGO.to_string(),
            body_class: String::new(),
            body_style: String::new(),
        }
    }
}

fn find_image(folder: &Path, stem: &str) -> Option<String> {
    IMAGE_EXTENSIONS
        .iter()
        .map(|ext| format!("{}.{}", stem, ext))
        .find(|file| folder.join(file).is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_folder(name: &str) -> PathBuf {
        let folder =
            std::env::temp_dir().join(format!("fakeidp-styling-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&folder);
        fs::create_dir_all(&folder).unwrap();
        folder
    }

    #[test]
    fn test_no_folder_keeps_the_defaults() {
        assert_eq!(Styling::default().branding(), Branding::default());
    }

    #[test]
    fn test_empty_folder_keeps_the_defaults() {
        let folder = temp_folder("empty");
        assert_eq!(
            Styling::new(Some(folder.clone())).branding(),
            Branding::default()
        );
        fs::remove_dir_all(folder).unwrap();
    }

    #[test]
    fn test_files_in_the_folder_are_picked_up() {
        let folder = temp_folder("full");
        fs::write(folder.join("custom.css"), "body {}").unwrap();
        fs::write(folder.join("logo.png"), "").unwrap();
        fs::write(folder.join("logo.svg"), "").unwrap();
        fs::write(folder.join("background.jpg"), "").unwrap();

        let branding = Styling::new(Some(folder.clone())).branding();
        assert_eq!(
            branding.stylesheet,
            r#"<link href="/styling/custom.css" rel="stylesheet">"#
        );
        // svg is looked for first
        assert_eq!(branding.logo, "/styling/logo.svg");
        assert_eq!(branding.body_class, " theme-body--image");
        assert_eq!(
            branding.body_style,
            r#" style="background-image: url('/styling/background.jpg')""#
        );
        fs::remove_dir_all(folder).unwrap();
    }
}
