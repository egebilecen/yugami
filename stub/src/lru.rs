use std::fmt::Display;

use proc_macros::xor_str;

const INVALID_PAGE: usize = usize::MAX;

#[derive(Copy, Clone)]
pub(crate) struct LruPageList<const N: usize> {
    pages: [usize; N],
}

impl<const N: usize> LruPageList<N> {
    pub fn new() -> Self {
        Self {
            pages: [INVALID_PAGE; N],
        }
    }

    /// Adds a page as MRU. Promotes if already present; evicts LRU if full.
    ///
    /// Returns `Some(evicted_page)` if a valid page was evicted, otherwise `None`.
    pub fn add(&mut self, page: usize) -> Option<usize> {
        if self.get(page).is_some() {
            return None;
        }

        let evicted_page = self.shift_left();
        self.pages[N - 1] = page;

        if evicted_page != INVALID_PAGE {
            Some(evicted_page)
        } else {
            None
        }
    }

    /// Looks up a page. If found, promotes it to MRU and returns `Some(page)`.
    pub fn get(&mut self, page: usize) -> Option<usize> {
        for (i, val) in self.pages.iter().enumerate().rev() {
            if page == *val {
                self.promote(i);
                return Some(page);
            }
        }

        None
    }

    /// Moves the page at `page_index` to the MRU position (`N - 1`).
    fn promote(&mut self, page_index: usize) {
        if page_index == N - 1 {
            return;
        }

        for i in page_index..N - 1 {
            let temp = self.pages[i + 1];
            self.pages[i + 1] = self.pages[i];
            self.pages[i] = temp;
        }
    }

    /// Shifts all elements left by one, evicting `pages[0]` (LRU) and setting `pages[N - 1]` to `NO_PAGE`.
    fn shift_left(&mut self) -> usize {
        let evicted_page = self.pages[0];

        for i in 0..N - 1 {
            self.pages[i] = self.pages[i + 1];
        }

        self.pages[N - 1] = INVALID_PAGE;
        evicted_page
    }
}

impl<const N: usize> Display for LruPageList<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", xor_str!("(LRU) "))?;

        for (i, page) in self.pages.iter().enumerate() {
            if *page == INVALID_PAGE {
                write!(f, "{}", xor_str!("INVALID"))?;
            } else {
                write!(f, "{}", page)?;
            }

            if i + 1 < N {
                write!(f, "{}", xor_str!(" -> "))?;
            }
        }

        write!(f, " (MRU)")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::LruPageList;
    use crate::lru::INVALID_PAGE;

    #[test]
    fn add() {
        let mut lru = LruPageList::<3>::new();
        assert_eq!(lru.pages, [INVALID_PAGE; 3]);

        assert_eq!(lru.add(1), None);
        assert_eq!(lru.pages, [INVALID_PAGE, INVALID_PAGE, 1]);

        assert_eq!(lru.add(2), None);
        assert_eq!(lru.pages, [INVALID_PAGE, 1, 2]);

        assert_eq!(lru.add(3), None);
        assert_eq!(lru.pages, [1, 2, 3]);

        assert_eq!(lru.add(4), Some(1));
        assert_eq!(lru.pages, [2, 3, 4]);

        assert_eq!(lru.add(5), Some(2));
        assert_eq!(lru.pages, [3, 4, 5]);

        // ─────────────────────────────────────────────────────────────

        let mut lru2 = LruPageList::<1>::new();

        assert_eq!(lru2.add(1), None);
        assert_eq!(lru2.pages, [1]);

        assert_eq!(lru2.add(2), Some(1));
        assert_eq!(lru2.pages, [2]);

        assert_eq!(lru2.add(3), Some(2));
        assert_eq!(lru2.pages, [3]);
    }

    #[test]
    fn get() {
        const CAPACITY: usize = 4;
        let mut lru = LruPageList::<CAPACITY>::new();

        for i in 1..=CAPACITY {
            lru.add(i);
        }

        assert_eq!(lru.get(1), Some(1));
        assert_eq!(lru.pages[CAPACITY - 1], 1);

        for _ in 0..2 {
            assert_eq!(lru.get(3), Some(3));
            assert_eq!(lru.pages[CAPACITY - 1], 3);
        }

        assert_eq!(lru.get(0xDEADBABE), None);
    }
}
