package repository

import (
	"context"

	"github.com/sjzar/chatlog/internal/model"
)

func (r *Repository) GetMedia(ctx context.Context, _type string, key string) (*model.Media, error) {
	return r.ds.GetMedia(ctx, _type, key)
}

func (r *Repository) GetMediaByName(ctx context.Context, _type string, name string, size int64) (*model.Media, error) {
	return r.ds.GetMediaByName(ctx, _type, name, size)
}
