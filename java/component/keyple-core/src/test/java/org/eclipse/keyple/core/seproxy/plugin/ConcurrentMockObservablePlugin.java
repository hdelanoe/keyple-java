package org.eclipse.keyple.core.seproxy.plugin;

import org.eclipse.keyple.core.seproxy.SeReader;
import org.eclipse.keyple.core.seproxy.exception.KeypleBaseException;
import org.eclipse.keyple.core.seproxy.exception.KeypleReaderException;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.mockito.Mockito.when;

public class ConcurrentMockObservablePlugin extends AbstractThreadedObservablePlugin {
    private static final Logger logger =
            LoggerFactory.getLogger(ConcurrentMockObservablePlugin.class);

    /*
     * Use a CopyOnWriteArrayList to avoid concurrency problem when the AbstractThreadedObservablePlugin
     * is polling the method AbstractThreadedObservablePlugin#fetchNativeReadersNames
     */
    List<String> readerNames = new CopyOnWriteArrayList<String>();
    String readerName = "1";
    /**
     * Instantiates a observable plugin.
     *
     * @param name name of the plugin
     */
    protected ConcurrentMockObservablePlugin(String name) {
        super(name);

        /*
         * spam the readerNames list with add/remove entry each milliseconds
         */
        new Thread(new Runnable(){

            @Override
            public void run() {
                Boolean even = true;
                while(true){

                    if(even){
                        readerNames.add(readerName);
                        logger.trace("add one element : {}", readerName);
                        even=false;
                    }else{
                        logger.trace("remove one element : {}", readerName);
                        readerNames.remove(readerName);
                        even=true;
                    }
                    try {
                        Thread.sleep(1);
                    } catch (InterruptedException ex) {
                        ex.printStackTrace();
                    }
                }
            }
        }).start();
    }

    @Override
    protected SortedSet<String> fetchNativeReadersNames() throws KeypleReaderException {
        return new TreeSet<String>(readerNames);
    }

    @Override
    protected SeReader fetchNativeReader(String name) throws KeypleReaderException {
        SeReader mock = Mockito.mock(SeReader.class);
        when(mock.getName()).thenReturn(readerName);
        return mock;
    }

    @Override
    protected SortedSet<SeReader> initNativeReaders() throws KeypleReaderException {
        SortedSet<SeReader> readers = new TreeSet<SeReader>();
        return readers;
    }

    @Override
    public Map<String, String> getParameters() {
        return null;
    }

    @Override
    public void setParameter(String key, String value) throws IllegalArgumentException, KeypleBaseException {

    }
}
