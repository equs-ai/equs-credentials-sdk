use async_lock::{Mutex, RwLock};
use std::cmp::Eq;
use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::pin::Pin;
use std::sync::Arc;

// Type for a boxed Future that can be used in async contexts
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// Unique identifier for handlers
type HandlerId = usize;
// Handler pointer is now an async function
type HandlerPtr<T> = Box<dyn Fn(T) -> BoxFuture<'static, ()> + Send + Sync + 'static>;

#[derive(Clone)]
pub struct EventEmitter<T: Hash + Eq + Clone + Send + Sync + 'static, U: Clone + Send + 'static> {
    #[allow(clippy::type_complexity)]
    handlers: Arc<RwLock<HashMap<T, HashMap<HandlerId, HandlerPtr<U>>>>>,
    next_handler_id: Arc<RwLock<HandlerId>>,
}

pub struct Subscription {
    id: HandlerId,
}

impl Subscription {
    fn new(id: HandlerId) -> Self {
        Self { id }
    }

    pub fn id(&self) -> HandlerId {
        self.id
    }
}

impl<T: Hash + Eq + Clone + Send + Sync + 'static, U: Clone + Send> EventEmitter<T, U> {
    /// Creates a new instance of `EventEmitter`.
    pub fn new() -> Self {
        Self {
            handlers: Arc::new(RwLock::new(HashMap::new())),
            next_handler_id: Arc::new(RwLock::new(0)),
        }
    }

    /// Registers an async function `handler` as a listener for `event` and returns a subscription
    /// that can be used to unsubscribe later.
    pub async fn on<F, Fut>(&self, event: T, handler: F) -> Subscription
    where
        F: Fn(U) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        // Convert any future-returning function into a BoxFuture
        let boxed_handler = Box::new(move |payload: U| -> BoxFuture<'static, ()> {
            let fut = handler(payload);
            Box::pin(fut)
        });

        let handler_id = {
            let mut handler_id = self.next_handler_id.write().await;
            *handler_id += 1;
            handler_id.to_owned()
        };

        {
            let mut handlers = self.handlers.write().await;
            let event_handlers = handlers.entry(event).or_insert_with(HashMap::new);
            event_handlers.insert(handler_id, boxed_handler);
        }

        Subscription::new(handler_id)
    }

    /// Removes a specific event listener using its subscription
    pub async fn off(&mut self, event: T, subscription: Subscription) -> bool {
        let mut handlers = self.handlers.write().await;
        if let Some(event_handlers) = handlers.get_mut(&event) {
            return event_handlers.remove(&subscription.id()).is_some();
        }
        false
    }

    /// Removes all listeners for a specific event
    pub async fn remove_all_listeners(&self, event: &T) -> bool {
        let mut handlers = self.handlers.write().await;
        handlers.remove(event).is_some()
    }

    /// Asynchronously invokes all listeners for the event.
    /// Handlers are executed concurrently but the method waits for all to complete.
    pub async fn emit(&self, event: T, payload: U) {
        let mut futures: Vec<BoxFuture<()>> = vec![];
        if let Some(handlers) = self.handlers.read().await.get(&event) {
            // Create futures for all handlers
            for handler in handlers.values() {
                let future = handler(payload.clone());
                futures.push(future);
            }
        }

        futures::future::join_all(futures).await;
    }

    /// Creates an observable for a specific event
    pub fn observable(&self, event: T) -> EventObservable<U> {
        let (sender, receiver) = async_channel::unbounded();

        // Set up an observable that will receive events via the channel
        EventObservable {
            receiver,
            _sender: Arc::new(Mutex::new(sender)),
        }
    }

    /// A convenience method to attach an observer to an event
    pub async fn observe(&mut self, event: T) -> (Subscription, EventObservable<U>) {
        let (tx, rx) = async_channel::unbounded();
        let sender = Arc::new(Mutex::new(tx));

        // Create the handler that will forward events to the channel
        let sender_clone = sender.clone();
        let subscription = self
            .on(event, move |payload| {
                let sender = sender_clone.clone();
                let payload_clone = payload.clone();

                // Return a future that sends the payload through the channel
                async move {
                    let _ = sender.lock().await.send(payload_clone).await;
                }
            })
            .await;

        let observable = EventObservable {
            receiver: rx,
            _sender: sender,
        };

        (subscription, observable)
    }
}

pub struct EventObservable<U: Clone> {
    receiver: async_channel::Receiver<U>,
    // Keep the sender around to maintain the connection
    _sender: Arc<Mutex<async_channel::Sender<U>>>,
}

impl<U: Clone> EventObservable<U> {
    /// Blocks until the next event is received
    pub async fn next(&self) -> Option<U> {
        self.receiver.recv().await.ok()
    }

    /// Non-blocking attempt to receive an event
    pub async fn try_next(&self) -> Option<U> {
        self.receiver.try_recv().ok()
    }

    /// Executes the provided function for each event received
    pub async fn subscribe<F>(&self, mut callback: F)
    where
        F: FnMut(U),
    {
        while let Ok(value) = self.receiver.recv().await {
            callback(value);
        }
    }
}
