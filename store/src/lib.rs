use std::collections::{HashMap, VecDeque};
use tokio::sync::{
    mpsc::{channel, Sender},
    oneshot,
};

#[cfg(test)]
#[path = "tests/store_tests.rs"]
pub mod store_tests;

pub type StoreError = rocksdb::Error;
type StoreResult<T> = Result<T, StoreError>;

type Key = Vec<u8>;
type Value = Vec<u8>;

pub enum StoreCommand {
    Write(Key, Value),
    WriteBatch(Vec<(Key, Value)>),
    Read(Key, oneshot::Sender<StoreResult<Option<Value>>>),
    NotifyRead(Key, oneshot::Sender<StoreResult<Value>>),
    Delete(Key),
}

#[derive(Clone)]
pub struct Store {
    channel: Sender<StoreCommand>,
}

impl Store {
    pub fn new(path: &str) -> StoreResult<Self> {
        let db = rocksdb::DB::open_default(path)?;
        let mut obligations = HashMap::<_, VecDeque<oneshot::Sender<_>>>::new();
        let (tx, mut rx) = channel(100);
        tokio::spawn(async move {
            while let Some(command) = rx.recv().await {
                match command {
                    StoreCommand::Write(key, value) => {
                        let _ = db.put(&key, &value);
                        if let Some(mut senders) = obligations.remove(&key) {
                            while let Some(s) = senders.pop_front() {
                                let _ = s.send(Ok(value.clone()));
                            }
                        }
                    }
                    StoreCommand::WriteBatch(pairs) => {
                        let mut batch = rocksdb::WriteBatch::default();
                        for (k, v) in &pairs {
                            batch.put(k, v);
                        }
                        let _ = db.write(batch);
                        // Fire any notify_read listeners for keys in this batch.
                        for (k, v) in pairs {
                            if let Some(mut senders) = obligations.remove(&k) {
                                while let Some(s) = senders.pop_front() {
                                    let _ = s.send(Ok(v.clone()));
                                }
                            }
                        }
                    }
                    StoreCommand::Delete(key) => {
                        let _ = db.delete(&key);
                    }
                    StoreCommand::Read(key, sender) => {
                        let response = db.get(&key);
                        let _ = sender.send(response);
                    }
                    StoreCommand::NotifyRead(key, sender) => {
                        let response = db.get(&key);
                        match response {
                            Ok(None) => obligations
                                .entry(key)
                                .or_insert_with(VecDeque::new)
                                .push_back(sender),
                            _ => {
                                let _ = sender.send(response.map(|x| x.unwrap()));
                            }
                        }
                    }
                }
            }
        });
        Ok(Self { channel: tx })
    }

    pub async fn write(&mut self, key: Key, value: Value) {
        if let Err(e) = self.channel.send(StoreCommand::Write(key, value)).await {
            panic!("Failed to send Write command to store: {}", e);
        }
    }

    pub async fn read(&mut self, key: Key) -> StoreResult<Option<Value>> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self.channel.send(StoreCommand::Read(key, sender)).await {
            panic!("Failed to send Read command to store: {}", e);
        }
        receiver
            .await
            .expect("Failed to receive reply to Read command from store")
    }

    pub async fn write_batch(&mut self, pairs: Vec<(Key, Value)>) {
        if let Err(e) = self.channel.send(StoreCommand::WriteBatch(pairs)).await {
            panic!("Failed to send WriteBatch command to store: {}", e);
        }
    }

    pub async fn delete(&mut self, key: Key) {
        if let Err(e) = self.channel.send(StoreCommand::Delete(key)).await {
            panic!("Failed to send Delete command to store: {}", e);
        }
    }

    pub async fn notify_read(&mut self, key: Key) -> StoreResult<Value> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self
            .channel
            .send(StoreCommand::NotifyRead(key, sender))
            .await
        {
            panic!("Failed to send NotifyRead command to store: {}", e);
        }
        receiver
            .await
            .expect("Failed to receive reply to NotifyRead command from store")
    }
}
