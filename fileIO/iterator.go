package fileIO

import (
	"io"
	"sync"

	"github.com/targodan/go-errors"
)

type Iterator interface {
	Next() (*File, error)
	Close() error
}

type concatIterator struct {
	i         int
	iterators []Iterator
}

func Concat(iterators ...Iterator) Iterator {
	return &concatIterator{
		i:         0,
		iterators: iterators,
	}
}

func (it *concatIterator) Next() (*File, error) {
	if it.i >= len(it.iterators) {
		return nil, io.EOF
	}

	f, err := it.iterators[it.i].Next()
	if err == io.EOF {
		it.i++
		return it.Next()
	}
	return f, err
}

func (it *concatIterator) Close() error {
	var err error
	for _, iterator := range it.iterators {
		err = errors.NewMultiError(err, iterator.Close())
	}
	return err
}

type concurrentIterator struct {
	iterators []Iterator
	c         chan *nextEntry
	wg        *sync.WaitGroup
	closed    bool
}

func Concurrent(iterators ...Iterator) Iterator {
	it := &concurrentIterator{
		iterators: iterators,
		c:         make(chan *nextEntry),
		wg:        new(sync.WaitGroup),
	}

	it.wg.Add(len(iterators))
	for i := range iterators {
		go it.consume(i)
	}

	go func() {
		it.wg.Wait()
		close(it.c)
	}()

	return it
}

func (it *concurrentIterator) consume(i int) {
	defer func() {
		it.wg.Done()
	}()

	for {
		f, err := it.iterators[i].Next()
		if err == io.EOF {
			break
		}

		it.c <- &nextEntry{
			File: f,
			Err:  err,
		}
	}
}

func (it *concurrentIterator) Next() (*File, error) {
	if it.closed {
		return nil, io.EOF
	}

	next := <-it.c
	if next == nil {
		return nil, io.EOF
	}

	return next.File, next.Err
}

func (it *concurrentIterator) Close() error {
	if it.closed {
		return nil
	}
	it.closed = true

	var err error
	for _, iterator := range it.iterators {
		err = errors.NewMultiError(err, iterator.Close())
	}
	return err
}
