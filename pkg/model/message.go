package model

import "time"

type Message struct {
	Payload string `json:"payload"`
	Time    int64  `json:"time"`
}

func NewMessage(payload string) Message {
	return Message{
		Payload: payload,
		Time:    time.Now().Unix(),
	}
}

func NewMessageWithTimestamp(payload string, time int64) Message {
	return Message{
		Payload: payload,
		Time:    time,
	}
}
