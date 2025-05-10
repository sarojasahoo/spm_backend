package com.spm.portfolio.repository;

import com.spm.portfolio.model.StockList;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface StockListRepository extends R2dbcRepository<StockList, Long> {
    Flux<StockList> findByUserId(String userId);
    Mono<StockList> findByStockSymbol(String stockSymbol);

    Mono<StockList> findByStockSymbolAndUserId(String stockSymbol,String userId);
    Mono<Void> deleteByStockSymbol(String stockName);
}
