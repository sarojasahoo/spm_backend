package com.spm.portfolio.service;

import com.spm.portfolio.model.StockList;
import com.spm.portfolio.repository.StockListRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
@Slf4j
public class StockListService {

    private final StockListRepository stockListRepository;
    // Fetch all stocks for a given user
    public Flux<StockList> getStocksByUserId(String userId) {
        return stockListRepository.findByUserId(userId);
    }

    // Add a stock to the list with transaction management
    @Transactional
    public Mono<StockList> addStock(StockList stock) {
        Mono<StockList> stockListMono = stockListRepository.findByStockSymbol(stock.getStockSymbol());
        return stockListMono.flatMap(scrip -> {
            log.info("Stock already present in stock list {}",scrip.getStockSymbol());
            return Mono.just(scrip);
        }).switchIfEmpty(Mono.defer(() -> {
            log.info("Adding Stock {} details to stock list for user {}",stock.getStockSymbol(),stock.getUserId());
                  return  stockListRepository.save(stock);
                }
        ));
    }

    @Transactional
    public Mono<Void> deleteByStockSymbol(String stockName) {
        return stockListRepository.deleteByStockSymbol(stockName);
    }
}
