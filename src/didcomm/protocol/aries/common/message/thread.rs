use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct Thread {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pthid: Option<String>,
}

impl Thread {
    pub fn new() -> Thread {
        Thread::default()
    }
    pub fn from_parent(parent: &Thread) -> Thread {
        Thread {
            pthid: parent.thid.clone(),
            ..Default::default()
        }
    }
    pub fn set_thid(mut self, thid: String) -> Thread {
        self.thid = Some(thid);
        self
    }
    pub fn set_pthid(mut self, pthid: String) -> Thread {
        self.pthid = Some(pthid);
        self
    }
    pub fn set_opt_pthid(mut self, pthid: Option<String>) -> Thread {
        self.pthid = pthid;
        self
    }
    pub fn is_reply(&self, id: &str) -> bool {
        self.thid.as_deref().unwrap_or_default() == id
    }
}

#[macro_export]
macro_rules! threadlike (($type:ident) => (
    impl $type {
        pub fn set_thread(mut self, thread: Thread) -> $type {
            self.thread = Some(thread);
            self
        }

        pub fn set_thread_id(mut self, id: &str) -> Self {
            self.thread = Some(Thread::new().set_thid(id.to_string()));
            self
        }

        pub fn set_pthid(mut self, pthid: &str) -> $type {
            self.thread = Some(Thread::new().set_pthid(pthid.to_string()));
            self
        }
    }
));

#[cfg(test)]
mod tests {
    use super::*;

    const THID: &str = "id";

    #[test]
    fn test_thread_new() {
        let thread = Thread::new();
        let expected = Thread {
            thid: None,
            pthid: None,
        };
        assert_eq!(expected, thread);
    }

    #[test]
    fn test_thread_set_thid() {
        let thread = Thread::new().set_thid(THID.to_string());

        assert_eq!(THID, thread.thid.unwrap());
    }

    #[test]
    fn test_thread_is_reply() {
        let thread = Thread::new();
        assert!(!thread.is_reply(THID));

        let thread = Thread::new().set_thid(THID.to_string());

        assert!(thread.is_reply(THID));
        assert!(!thread.is_reply("other"));
    }
}
